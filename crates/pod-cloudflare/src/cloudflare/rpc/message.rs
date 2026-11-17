//! The messages of the RPC session: the readers of a Return and the
//! builders of the answers that the client sends.

use super::*;

pub(crate) fn exception_reason(ret: &StructReader<'_>) -> Result<String> {
    Ok(ret.get_struct(0)?.map(|e| e.get_text(0).unwrap_or_default()).unwrap_or_default())
}

/// The `Payload` of a `Return` with results.
pub(crate) fn payload<'a>(message: &'a Message) -> Result<StructReader<'a>> {
    message
        .root()?
        .get_struct(0)?
        .or_fail(Stage::EdgeRegister, Class::Protocol, "an empty Return")?
        .get_struct(0)?
        .or_fail(Stage::EdgeRegister, Class::Protocol, "a Return with no payload")
}

/// The content struct of the results.
pub(crate) fn results_struct(message: &Message) -> Result<StructReader<'_>> {
    payload(message)?.get_struct(0)?.or_fail(Stage::EdgeRegister, Class::Protocol, "the results have no content")
}

/// The import id of the capability in the results of a bootstrap.
pub(crate) fn imported_capability(message: &Message) -> Result<u32> {
    let payload = payload(message)?;
    let index = payload.get_capability(0)?.or_fail(
        Stage::EdgeRegister,
        Class::Protocol,
        "the bootstrap answer has no capability",
    )?;
    let table = payload.get_struct_list(1)?;
    let descriptor = table.get(index as usize).or_fail(
        Stage::EdgeRegister,
        Class::Protocol,
        "the capability is not in the cap table",
    )?;
    match descriptor.get_u16(0) {
        CAP_SENDER_HOSTED | CAP_SENDER_PROMISE => Ok(descriptor.get_u32(1)),
        other => bail!(Stage::EdgeRegister, Class::Protocol, "unsupported capability descriptor {other}"),
    }
}

/// `Finish` for `question`.
pub(super) fn finish(question: u32, release_result_caps: bool) -> Builder {
    let mut b = Builder::new();
    let root = b.init_root(1, 1);
    b.set_u16(root, 0, MSG_FINISH);
    let f = b.init_struct(root, 0, 1, 0);
    b.set_u32(f, 0, question);
    // The default of releaseResultCaps is true: the stored bit is the XOR.
    b.set_bool(f, 32, !release_result_caps);
    b
}

/// The answer to a `Bootstrap` of the edge: the capability of the client,
/// export 0.
pub(crate) fn our_bootstrap_return(question: u32) -> Builder {
    let mut b = Builder::new();
    let root = b.init_root(1, 1);
    b.set_u16(root, 0, MSG_RETURN);
    // Return: 2 data words, 1 pointer.
    let ret = b.init_struct(root, 0, 2, 1);
    b.set_u32(ret, 0, question);
    b.set_u16(ret, 3, RETURN_RESULTS);
    let payload = b.init_struct(ret, 0, 0, 2);
    b.set_capability(payload, 0, 0);
    // CapDescriptor: 1 data word, 1 pointer.
    let table = b.init_struct_list(payload, 1, 1, 1, 1);
    b.set_u16(table[0], 0, CAP_SENDER_HOSTED);
    b.set_u32(table[0], 1, OUR_EXPORT);
    b
}

/// A `Return` with an `unimplemented` exception for `question`.
pub(crate) fn exception_return(question: u32, reason: &str) -> Builder {
    let mut b = Builder::new();
    let root = b.init_root(1, 1);
    b.set_u16(root, 0, MSG_RETURN);
    let ret = b.init_struct(root, 0, 2, 1);
    b.set_u32(ret, 0, question);
    b.set_u16(ret, 3, RETURN_EXCEPTION);
    // Exception: 1 data word, 2 pointers; type is u16 at index 2.
    let exception = b.init_struct(ret, 0, 1, 2);
    b.set_text(exception, 0, reason);
    b.set_u16(exception, 2, EXCEPTION_UNIMPLEMENTED);
    b
}
