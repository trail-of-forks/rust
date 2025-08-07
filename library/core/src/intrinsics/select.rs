//! Constant-time selection intrinsics
//!
//! This module provides safe, high-level wrappers around the `ct_select` 
//! intrinsics for branchless conditional selection.

#![allow(internal_features)]
use crate::intrinsics;

/// Trait for types that support constant-time selection
///
/// This trait is implemented for all integer types and provides a consistent
/// interface for branchless conditional selection.
pub trait ConstantTimeSelect: Copy {
    /// Performs constant-time selection between two values
    ///
    /// Returns `true_val` if `cond` is true, otherwise returns `false_val`.
    /// This operation is designed to be branchless and compile to efficient
    /// machine code without conditional jumps.
    ///
    /// # Examples
    ///
    /// ```
    /// # #![feature(core_intrinsics)]
    /// # use core::intrinsics::select::ConstantTimeSelect;
    /// let result = u32::ct_select(true, 42, 17);
    /// assert_eq!(result, 42);
    ///
    /// let result = u32::ct_select(false, 42, 17);
    /// assert_eq!(result, 17);
    /// ```
    fn ct_select(cond: bool, true_val: Self, false_val: Self) -> Self;
}

/// High-level constant-time selection function
///
/// This is the primary API that users should use. It provides a generic
/// interface over all types that implement `ConstantTimeSelect`.
///
/// # Examples
///
/// ```
/// # #![feature(core_intrinsics)]
/// # use core::intrinsics::select::ct_select;
/// // Basic usage
/// let x = ct_select(true, 100u32, 200u32);
/// assert_eq!(x, 100);
///
/// // Branchless min/max
/// let a = 15u32;
/// let b = 23u32;
/// let min = ct_select(a <= b, a, b);
/// let max = ct_select(a >= b, a, b);
/// assert_eq!(min, 15);
/// assert_eq!(max, 23);
///
/// // Conditional arithmetic without branches
/// let should_negate = true;
/// let value = 42i32;
/// let result = ct_select(should_negate, -value, value);
/// assert_eq!(result, -42);
/// ```
///
/// # Performance Notes
///
/// This function is designed to compile to branchless code, which can be
/// beneficial in cryptographic contexts or when avoiding timing side channels
/// is important. However, for simple conditionals, regular `if` expressions
/// may be more readable and equally performant.
#[inline(always)]
pub fn ct_select<T>(cond: bool, true_val: T, false_val: T) -> T
where
    T: ConstantTimeSelect,
{
    T::ct_select(cond, true_val, false_val)
}

// Macro to implement ConstantTimeSelect for integer types
macro_rules! impl_constant_time_select {
    ($ty:ty, $intrinsic:ident) => {
        impl ConstantTimeSelect for $ty {
            #[inline(always)]
            fn ct_select(cond: bool, true_val: Self, false_val: Self) -> Self {
                intrinsics::$intrinsic(cond, true_val, false_val)
            }
        }
    };
}

// Implement for all integer types
impl_constant_time_select!(i8, ct_select_i8);
impl_constant_time_select!(i16, ct_select_i16);
impl_constant_time_select!(i32, ct_select_i32);
impl_constant_time_select!(i64, ct_select_i64);
