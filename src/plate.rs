pub fn canonical_plate_key(plate: &str) -> String {
    plate
        .trim()
        .to_ascii_uppercase()
        .replace('O', "0")
        .replace('I', "1")
}

pub fn same_plate_family(left: &str, right: &str) -> bool {
    canonical_plate_key(left) == canonical_plate_key(right)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn common_ocr_variants_share_one_key() {
        assert_eq!(canonical_plate_key(" aboi "), "AB01");
        assert!(same_plate_family("ABOI", "ab01"));
        assert!(!same_plate_family("ABC123", "ABC128"));
    }
}
