//! GUIDs identifying WFP objects

use std::fmt;

use windows_sys::core::GUID;

/// A globally unique identifier for a WFP object, such as a filter, sublayer or provider.
///
/// # Example
///
/// ```
/// use wfp::Guid;
///
/// let guid = Guid::from_u128(0x11111111_2222_3333_4444_555555555555);
/// assert_eq!(format!("{guid:?}"), "11111111-2222-3333-4444-555555555555");
/// ```
#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

impl Guid {
    /// Construct a GUID from its integer representation, e.g.
    /// `0x11111111_2222_3333_4444_555555555555`.
    pub const fn from_u128(guid: u128) -> Self {
        Self::from_raw(GUID::from_u128(guid))
    }

    /// Copy the fields of a [`GUID`].
    ///
    /// This is the [`From`] implementation, which cannot itself be `const`.
    pub(crate) const fn from_raw(guid: GUID) -> Self {
        Self {
            data1: guid.data1,
            data2: guid.data2,
            data3: guid.data3,
            data4: guid.data4,
        }
    }
}

impl From<GUID> for Guid {
    fn from(guid: GUID) -> Self {
        Self::from_raw(guid)
    }
}

impl From<&GUID> for Guid {
    fn from(guid: &GUID) -> Self {
        Self::from_raw(*guid)
    }
}

impl From<&Guid> for Guid {
    fn from(guid: &Guid) -> Self {
        *guid
    }
}

impl From<Guid> for GUID {
    fn from(guid: Guid) -> Self {
        Self {
            data1: guid.data1,
            data2: guid.data2,
            data3: guid.data3,
            data4: guid.data4,
        }
    }
}

impl fmt::Debug for Guid {
    /// Format the GUID in the canonical `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` form.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            data1,
            data2,
            data3,
            data4,
        } = self;
        write!(f, "{data1:08x}-{data2:04x}-{data3:04x}")?;
        let (group4, group5) = data4.split_at(2);
        for group in [group4, group5] {
            f.write_str("-")?;
            for byte in group {
                write!(f, "{byte:02x}")?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const GUID_U128: u128 = 0x11111111_2222_3333_4444_555555555555;

    #[test]
    fn test_guid_eq() {
        assert_eq!(Guid::from_u128(GUID_U128), Guid::from_u128(GUID_U128));
        assert_ne!(Guid::from_u128(GUID_U128), Guid::from_u128(GUID_U128 + 1));
    }

    #[test]
    fn test_guid_roundtrip() {
        let guid = Guid::from_u128(GUID_U128);
        assert_eq!(Guid::from(GUID::from(guid)), guid);
    }

    #[test]
    fn test_guid_debug() {
        assert_eq!(
            format!("{:?}", Guid::from_u128(GUID_U128)),
            "11111111-2222-3333-4444-555555555555"
        );
    }
}
