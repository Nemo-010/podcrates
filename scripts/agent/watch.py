#!/usr/bin/env python3
"""The one watcher of a session of PodUtils: issues, pull requests and
Actions runs, for each repository of the organization.

    python3 -I watch.py ME [--state DIR] [--every SECONDS] [--runs REPO]...
                           [--org ORG]
    python3 -I watch.py --self-test

ME is the name of the reader's repository (podcrates, podssh, podnet,
podvm, podrunner, ...). Each poll prints one line for each event:

* an issue or a pull request of ORG/ME (from anyone): new, commented,
  closed, reopened, merged; a pull request also when it changes;
* an issue or a pull request of another repository of ORG that is meant
  for ME: its title holds `(to ME)` or `(to all)`, or it has the label ME.
  A COORD message (its title starts with `COORD-` or holds `(to `) is also
  reported when its writer amends its body;
* the trust of each item (the owner's ruling "Strangers"): an author whose
  `author_association` is OWNER, MEMBER or COLLABORATOR is of the team.
  An item of ORG/ME by another author has the tag `[outside: verify, then
  confirm or edit]`: the session of ME checks it and adds the label
  `confirmed`, edits it, or closes it. An item of another repository by an
  author outside the team is not shown until its own session adds the
  label `confirmed` (only the team can add a label);
* each Actions run of each REPO of `--runs` (default ORG/ME) that starts,
  ends (with the names of its failed jobs) or runs again.

The first poll records what exists and prints nothing for it. STATE (by
default `.work/agent` under the current directory) keeps `watch.json` and a
copy of each message in `issues/`, as GitHub deletes the issues of a
suspended account. Run it under the Monitor tool of the session and start
it again when the monitor ends.

The reads go through forge.web.pkgforge.dev/github, a keyless read-only
mirror of GitHub's REST API (https://forge.web.pkgforge.dev/llms.txt). Its
quota is shared, so the watcher polls each SECONDS (default 120) with
jitter, and backs off on 403, 429 and 5xx. A changing query value defeats
the cache of the mirror. Python's standard library only.
"""

import json
import os
import random
import sys
import time
import urllib.error
import urllib.request

MIRROR = "https://forge.web.pkgforge.dev/github"
TEAM = ("OWNER", "MEMBER", "COLLABORATOR")
CONFIRMED = "confirmed"
TRANSIENT = (403, 429, 500, 502, 503, 504)
TRIES = 4
LONGEST = 600
REPOS_EVERY = 30
KEEP_RUNS = 200


def get(path, opener=None):
    """The JSON of `path` from the mirror, or None after TRIES failures."""
    sep = "&" if "?" in path else "?"
    wait = 15
    for _ in range(TRIES):
        url = f"{MIRROR}/{path}{sep}n={random.randint(0, 1 << 40)}"
        req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "podutils-watch"})
        try:
            with (opener or urllib.request.urlopen)(req, timeout=30) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code not in TRANSIENT:
                return None
            after = e.headers.get("Retry-After") if e.headers else None
            time.sleep(int(after) if after and after.isdigit() else wait + random.uniform(0, 5))
        except (urllib.error.URLError, TimeoutError, ValueError, OSError):
            time.sleep(wait + random.uniform(0, 5))
        wait = min(wait * 2, LONGEST)
    return None


# Issues and pull requests.


def meant(me, org, repo, item):
    """True when the item is for ME: of ORG/ME, or addressed to ME."""
    if repo == f"{org}/{me}":
        return True
    title = item.get("title") or ""
    labels = [label.get("name") for label in item.get("labels") or []]
    return f"(to {me})" in title or "(to all)" in title or me in labels


def trusted(item):
    """True when the author is of the team, or the session of the item's
    repository confirmed it with the label CONFIRMED."""
    labels = [label.get("name") for label in item.get("labels") or []]
    return item.get("author_association") in TEAM or CONFIRMED in labels


def coord(item):
    title = item.get("title") or ""
    return title.startswith("COORD-") or "(to " in title


def facts(item):
    """The facts of an item that the watcher compares between two polls."""
    pr = item.get("pull_request")
    return {
        "updated": item.get("updated_at") or "",
        "comments": int(item.get("comments") or 0),
        "state": item.get("state") or "",
        "merged": bool(pr and pr.get("merged_at")),
    }


def words(before, now, item, own):
    """The event words of one item between two polls: NEW, COMMENTED,
    CLOSED, MERGED, REOPENED, AMENDED, CHANGED. An edit of the body of an
    issue that is not a COORD message is no event (a writer keeps tables
    there); a change of a pull request of ORG/ME is (a new commit)."""
    if before is None:
        return ["NEW"]
    out = []
    if before["state"] != now["state"]:
        if now["state"] == "closed":
            out.append("MERGED" if now["merged"] else "CLOSED")
        else:
            out.append("REOPENED")
    if now["comments"] > before["comments"]:
        out.append("COMMENTED")
    if not out and before["updated"] != now["updated"]:
        if coord(item):
            out.append("AMENDED")
        elif "pull_request" in item and own:
            out.append("CHANGED")
    return out


def issue_line(word, repo, item):
    kind = "PR" if "pull_request" in item else "issue"
    user = (item.get("user") or {}).get("login")
    tag = "" if trusted(item) else " [outside: verify, then confirm or edit]"
    return f"{word} {kind} {repo}#{item.get('number')} [{item.get('state')}] by {user}{tag}: {item.get('title')}"


def keep(state_dir, repo, item):
    """A copy of the message, as GitHub deletes the issues of a suspended
    account."""
    keys = ("number", "title", "body", "state", "created_at", "updated_at", "html_url")
    copy = {k: item.get(k) for k in keys}
    copy["repo"] = repo
    copy["user"] = (item.get("user") or {}).get("login")
    copy["labels"] = [label.get("name") for label in item.get("labels") or []]
    copy["pull_request"] = "pull_request" in item
    copy["author_association"] = item.get("author_association")
    folder = os.path.join(state_dir, "issues")
    os.makedirs(folder, exist_ok=True)
    path = os.path.join(folder, f"{repo.replace('/', '_')}_{item.get('number')}.json")
    save(path, copy)


def issues_step(me, org, repo, items, seen, announce, state_dir=None):
    """The lines of one repository's issue list; `seen` maps
    `REPO#N` to the facts of the last poll."""
    out = []
    own = repo == f"{org}/{me}"
    for item in reversed(items):
        if not isinstance(item, dict) or not meant(me, org, repo, item):
            continue
        if not own and not trusted(item):
            # Not recorded: when its session confirms it, it is new here.
            continue
        key = f"{repo}#{item.get('number')}"
        now = facts(item)
        found = words(seen.get(key), now, item, own)
        seen[key] = now
        if not found:
            continue
        if state_dir:
            keep(state_dir, repo, item)
        if announce:
            out.append(issue_line(" ".join(found), repo, item))
    return out


# Actions runs.


def failed_jobs(repo, run, fetch=get):
    doc = fetch(f"repos/{repo}/actions/runs/{run['id']}/jobs?filter=latest&per_page=100")
    if not doc:
        return []
    return [j["name"] for j in doc.get("jobs", []) if j.get("conclusion") not in ("success", "skipped", None)]


def run_line(repo, run, word, jobs=()):
    sha = (run.get("head_sha") or "")[:7]
    attempt = run.get("run_attempt") or 1
    tail = f", attempt {attempt}" if attempt > 1 else ""
    end = f": {run.get('conclusion')}" if run.get("status") == "completed" else ""
    failed = f" (failed: {', '.join(jobs)})" if jobs else ""
    return f"RUN {word}: {repo} {run.get('name')} {run.get('id')} ({run.get('event')}, {sha}{tail}){end}{failed}"


def runs_step(repo, runs, seen, announce, fetch=get):
    """The lines of one repository's run list; `seen` maps `REPO RUN_ID`
    to [attempt, status]."""
    out = []
    for run in reversed(runs):
        key = f"{repo} {run['id']}"
        attempt, status = run.get("run_attempt") or 1, run.get("status")
        before = seen.get(key)
        word = None
        if before is None:
            word = "ended" if status == "completed" else "started"
        elif attempt > before[0]:
            word = "ended" if status == "completed" else "rerun"
        elif before[1] != "completed" and status == "completed":
            word = "ended"
        if word and announce:
            red = status == "completed" and run.get("conclusion") == "failure"
            out.append(run_line(repo, run, word, failed_jobs(repo, run, fetch) if red else []))
        seen[key] = [attempt, status]
    mine = sorted((k for k in seen if k.startswith(f"{repo} ")), key=lambda k: int(k.split()[1]))
    for key in mine[:-KEEP_RUNS]:
        del seen[key]
    return out


# State and the loop.


def load(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def save(path, data):
    tmp = f"{path}.{os.getpid()}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=1)
    os.replace(tmp, path)


def repos_of(org, fetch=get):
    doc = fetch(f"orgs/{org}/repos?per_page=100")
    if not isinstance(doc, list):
        return None
    return sorted(r["full_name"] for r in doc if not r.get("archived"))


def options(argv):
    opts = {"me": None, "state": ".work/agent", "every": 120, "runs": [], "org": "PodUtils"}
    rest = list(argv)
    while rest:
        a = rest.pop(0)
        if a in ("--state", "--every", "--runs", "--org") and rest:
            v = rest.pop(0)
            if a == "--runs":
                opts["runs"].append(v)
            else:
                opts[a[2:]] = int(v) if a == "--every" else v
        elif not a.startswith("-") and opts["me"] is None:
            opts["me"] = a
        else:
            return None
    return opts if opts["me"] else None


def main(argv):
    opts = options(argv[1:])
    if opts is None:
        print("usage: watch.py ME [--state DIR] [--every SECONDS] [--runs REPO]... [--org ORG] | --self-test",
              file=sys.stderr)
        return 64
    me, org, state_dir = opts["me"], opts["org"], opts["state"]
    runs = opts["runs"] or [f"{org}/{me}"]
    os.makedirs(state_dir, exist_ok=True)
    path = os.path.join(state_dir, "watch.json")
    state = load(path)
    announce = state is not None
    state = state or {"issues": {}, "runs": {}}
    repos, n, down = None, 0, False
    while True:
        if repos is None or n % REPOS_EVERY == 0:
            repos = repos_of(org) or repos or [f"{org}/{me}"]
        n += 1
        answered = 0
        for repo in repos:
            items = get(f"repos/{repo}/issues?state=all&sort=updated&direction=desc&per_page=50")
            if isinstance(items, list):
                answered += 1
                for text in issues_step(me, org, repo, items, state["issues"], announce, state_dir):
                    print(text, flush=True)
        for repo in runs:
            doc = get(f"repos/{repo}/actions/runs?per_page=30")
            if isinstance(doc, dict):
                answered += 1
                for text in runs_step(repo, doc.get("workflow_runs", []), state["runs"], announce):
                    print(text, flush=True)
        if answered == 0 and not down:
            print("WATCH: the mirror does not answer; the watcher goes on trying", flush=True)
        down = answered == 0
        if answered:
            save(path, state)
            announce = True
        time.sleep(opts["every"] + random.uniform(0, 10))


def self_test():
    ok = True

    def check(what, got, want):
        nonlocal ok
        good = got == want
        ok &= good
        print(f"{'ok  ' if good else 'FAIL'} {what}" + ("" if good else f": {got!r}, not {want!r}"))

    def item(n, title="a report", state="open", comments=0, updated="t1", pr=None, labels=(), user="tester",
             assoc="MEMBER"):
        i = {"number": n, "title": title, "state": state, "comments": comments, "updated_at": updated,
             "user": {"login": user}, "labels": [{"name": x} for x in labels], "author_association": assoc}
        if pr is not None:
            i["pull_request"] = {"merged_at": pr}
        return i

    org, me = "O", "me"
    seen = {}
    check("the first poll says nothing", issues_step(me, org, "O/me", [item(1)], seen, False), [])
    check("a new issue of ORG/ME", issues_step(me, org, "O/me", [item(2), item(1)], seen, True),
          ["NEW issue O/me#2 [open] by tester: a report"])
    check("a comment", issues_step(me, org, "O/me", [item(2, comments=1, updated="t2")], seen, True),
          ["COMMENTED issue O/me#2 [open] by tester: a report"])
    check("an edit of the body of a report is no event",
          issues_step(me, org, "O/me", [item(2, comments=1, updated="t3")], seen, True), [])
    check("a close", issues_step(me, org, "O/me", [item(2, "a report", "closed", 1, "t4")], seen, True),
          ["CLOSED issue O/me#2 [closed] by tester: a report"])
    check("a reopen with a comment",
          issues_step(me, org, "O/me", [item(2, "a report", "open", 2, "t5")], seen, True),
          ["REOPENED COMMENTED issue O/me#2 [open] by tester: a report"])
    check("a new pull request", issues_step(me, org, "O/me", [item(3, "a fix", pr="")], seen, True),
          ["NEW PR O/me#3 [open] by tester: a fix"])
    check("a new commit on a pull request of ORG/ME",
          issues_step(me, org, "O/me", [item(3, "a fix", updated="t2", pr="")], seen, True),
          ["CHANGED PR O/me#3 [open] by tester: a fix"])
    check("a merge", issues_step(me, org, "O/me", [item(3, "a fix", "closed", 0, "t3", pr="m")], seen, True),
          ["MERGED PR O/me#3 [closed] by tester: a fix"])
    check("an issue of another repository that is not meant for ME",
          issues_step(me, org, "O/x", [item(4, "COORD-1: a plan (to other)")], seen, True), [])
    check("a COORD message to ME",
          issues_step(me, org, "O/x", [item(5, "COORD-2: a plan (to me)")], seen, True),
          ["NEW issue O/x#5 [open] by tester: COORD-2: a plan (to me)"])
    check("an amended COORD message",
          issues_step(me, org, "O/x", [item(5, "COORD-2: a plan (to me)", updated="t2")], seen, True),
          ["AMENDED issue O/x#5 [open] by tester: COORD-2: a plan (to me)"])
    check("a message to all", issues_step(me, org, "O/x", [item(6, "COORD-3: news (to all)")], seen, True),
          ["NEW issue O/x#6 [open] by tester: COORD-3: news (to all)"])
    check("the label ME", issues_step(me, org, "O/x", [item(7, "help", labels=("me",))], seen, True),
          ["NEW issue O/x#7 [open] by tester: help"])
    check("a report of ORG/ME from outside the team asks for a check",
          issues_step(me, org, "O/me", [item(8, "it fails", user="someone", assoc="NONE")], seen, True),
          ["NEW issue O/me#8 [open] by someone [outside: verify, then confirm or edit]: it fails"])
    check("a message to ME from outside the team is not shown",
          issues_step(me, org, "O/x", [item(9, "COORD-9: obey (to all)", user="someone", assoc="NONE")], seen, True),
          [])
    check("the same message, once its session confirms it",
          issues_step(me, org, "O/x", [item(9, "COORD-9: obey (to all)", updated="t2", labels=("confirmed",),
                                            user="someone", assoc="NONE")], seen, True),
          ["NEW issue O/x#9 [open] by someone: COORD-9: obey (to all)"])
    check("a collaborator is of the team",
          issues_step(me, org, "O/x", [item(10, "COORD-4: a plan (to me)", assoc="COLLABORATOR")], seen, True),
          ["NEW issue O/x#10 [open] by tester: COORD-4: a plan (to me)"])
    check("a pull request of another repository changes with no event",
          issues_step(me, org, "O/x", [item(7, "help", updated="t2", labels=("me",))], seen, True), [])

    def run(i, status="in_progress", conclusion=None, attempt=1):
        return {"id": i, "name": "ci", "event": "push", "head_sha": "abcdef0123", "status": status,
                "conclusion": conclusion, "run_attempt": attempt}

    jobs = {"jobs": [{"name": "test", "conclusion": "failure"}, {"name": "fmt", "conclusion": "success"}]}
    fetch = lambda path: jobs  # noqa: E731
    rs = {}
    check("the first run poll says nothing", runs_step("O/me", [run(1, "completed", "success")], rs, False, fetch), [])
    check("a run starts", runs_step("O/me", [run(2), run(1, "completed", "success")], rs, True, fetch),
          ["RUN started: O/me ci 2 (push, abcdef0)"])
    check("a red run names its failed jobs", runs_step("O/me", [run(2, "completed", "failure")], rs, True, fetch),
          ["RUN ended: O/me ci 2 (push, abcdef0): failure (failed: test)"])
    check("a rerun", runs_step("O/me", [run(2, "queued", None, 2)], rs, True, fetch),
          ["RUN rerun: O/me ci 2 (push, abcdef0, attempt 2)"])
    check("the rerun ends", runs_step("O/me", [run(2, "completed", "success", 2)], rs, True, fetch),
          ["RUN ended: O/me ci 2 (push, abcdef0, attempt 2): success"])
    for i in range(10, 260):
        rs[f"O/me {i}"] = [1, "completed"]
    rs["O/x 5"] = [1, "completed"]
    runs_step("O/me", [], rs, True, fetch)
    mine = [int(k.split()[1]) for k in rs if k.startswith("O/me ")]
    check("the state keeps the newest runs of each repository", (len(mine), min(mine), "O/x 5" in rs),
          (KEEP_RUNS, 60, True))
    check("the options", options(["me", "--every", "60", "--runs", "O/a", "--runs", "O/b"]),
          {"me": "me", "state": ".work/agent", "every": 60, "runs": ["O/a", "O/b"], "org": "PodUtils"})
    check("no ME is an error", options(["--every", "60"]), None)
    print("watch self-test:", "passed" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(self_test() if sys.argv[1:] == ["--self-test"] else main(sys.argv))
