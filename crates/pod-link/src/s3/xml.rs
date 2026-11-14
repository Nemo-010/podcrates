//! The few parts of the XML of the S3 API that the carrier reads: the
//! objects of a listing (`ListObjectsV2`), its continuation, and the code
//! of an error. No other element matters, so no parser of XML is in the
//! build.

/// One object of a listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Object {
    pub key: String,
    pub etag: String,
    pub size: u64,
}

/// One page of a listing.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Listing {
    pub objects: Vec<Object>,
    /// The token of the next page, when the listing is cut.
    pub next: Option<String>,
}

/// The text of the first element `name` in `xml`, with no unescape.
fn element<'a>(xml: &'a str, name: &str) -> Option<&'a str> {
    let open = format!("<{name}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&format!("</{name}>"))? + start;
    Some(&xml[start..end])
}

/// Each element `name` in `xml`, in order.
fn elements<'a>(xml: &'a str, name: &str) -> Vec<&'a str> {
    let (open, close) = (format!("<{name}>"), format!("</{name}>"));
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(at) = rest.find(&open) {
        let body = &rest[at + open.len()..];
        let Some(end) = body.find(&close) else { break };
        out.push(&body[..end]);
        rest = &body[end + close.len()..];
    }
    out
}

/// The five entities of XML, and the references of characters.
pub fn unescape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        let tail = &rest[at..];
        let Some(end) = tail.find(';') else {
            out.push_str(tail);
            return out;
        };
        let name = &tail[1..end];
        let ch = match name {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ => name
                .strip_prefix("#x")
                .and_then(|h| u32::from_str_radix(h, 16).ok())
                .or_else(|| name.strip_prefix('#').and_then(|d| d.parse().ok()))
                .and_then(char::from_u32),
        };
        match ch {
            Some(ch) => out.push(ch),
            None => out.push_str(&tail[..=end]),
        }
        rest = &tail[end + 1..];
    }
    out.push_str(rest);
    out
}

/// A page of `ListObjectsV2`. An object with no key is left out.
pub fn listing(xml: &str) -> Listing {
    let objects = elements(xml, "Contents")
        .into_iter()
        .filter_map(|c| {
            let key = unescape(element(c, "Key")?);
            let etag = element(c, "ETag").map(unescape).unwrap_or_default();
            let size = element(c, "Size").and_then(|s| s.trim().parse().ok()).unwrap_or(0);
            Some(Object { key, etag, size })
        })
        .collect();
    let cut = element(xml, "IsTruncated").is_some_and(|t| t.trim() == "true");
    let next = element(xml, "NextContinuationToken").map(unescape).filter(|_| cut);
    Listing { objects, next }
}

/// The `Code` of an error of the S3 API, when the body has one.
pub fn error_code(xml: &str) -> Option<String> {
    element(xml, "Code").map(unescape)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_listing_gives_its_objects_and_its_next_page() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>b</Name><Prefix>p/up/</Prefix>
<Contents><Key>p/up/a&amp;b/0000000000000000</Key><LastModified>2026-11-14T00:00:00.000Z</LastModified>
<ETag>&quot;9e107d9d372bb6826bd81d3542a419d6&quot;</ETag><Size>43</Size></Contents>
<Contents><Key>p/up/x/0000000000000001</Key><ETag>"e2"</ETag><Size>0</Size></Contents>
<IsTruncated>true</IsTruncated><NextContinuationToken>t&lt;1</NextContinuationToken></ListBucketResult>"#;
        let page = listing(xml);
        assert_eq!(page.objects.len(), 2);
        assert_eq!(page.objects[0].key, "p/up/a&b/0000000000000000");
        assert_eq!(page.objects[0].etag, "\"9e107d9d372bb6826bd81d3542a419d6\"");
        assert_eq!((page.objects[0].size, page.objects[1].size), (43, 0));
        assert_eq!(page.next.as_deref(), Some("t<1"));
        let last = listing("<ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>");
        assert_eq!(last, Listing::default());
        assert_eq!(error_code("<Error><Code>NoSuchBucket</Code></Error>").as_deref(), Some("NoSuchBucket"));
        assert_eq!(unescape("&#65;&#x42;&bad;&"), "AB&bad;&");
    }
}
