//! Strongly typed virtual memory address.

use std::fmt;
use std::ops::{Add, AddAssign, Sub};

/// A virtual address inside a target process.
///
/// Wraps a `usize` so that 64-bit address spaces on a 64-bit host are exact.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Address(pub usize);

impl Address {
    pub const NULL: Address = Address(0);

    #[inline]
    pub const fn new(value: usize) -> Self {
        Address(value)
    }

    #[inline]
    pub const fn get(self) -> usize {
        self.0
    }

    /// Whether the address is aligned to `align` bytes (align <= 1 is always true).
    #[inline]
    pub const fn is_aligned_to(self, align: usize) -> bool {
        align <= 1 || self.0 % align == 0
    }

    /// Offset to the next aligned address at or after `self`.
    #[inline]
    pub const fn align_up(self, align: usize) -> Address {
        if align <= 1 {
            self
        } else {
            Address((self.0 + align - 1) / align * align)
        }
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:X}", self.0)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:X}", self.0)
    }
}

impl Add<usize> for Address {
    type Output = Address;
    #[inline]
    fn add(self, rhs: usize) -> Address {
        Address(self.0.wrapping_add(rhs))
    }
}

impl AddAssign<usize> for Address {
    #[inline]
    fn add_assign(&mut self, rhs: usize) {
        self.0 = self.0.wrapping_add(rhs);
    }
}

impl Sub<Address> for Address {
    type Output = usize;
    #[inline]
    fn sub(self, rhs: Address) -> usize {
        self.0.wrapping_sub(rhs.0)
    }
}

impl Sub<usize> for Address {
    type Output = Address;
    #[inline]
    fn sub(self, rhs: usize) -> Address {
        Address(self.0.wrapping_sub(rhs))
    }
}
