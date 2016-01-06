pub struct Name<'a>{
    labels: &'a [u8],
    /// This is the original buffer size. The compressed names in original
    /// are calculated in this buffer
    original: &'a [u8],
}

