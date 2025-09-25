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

// --- min / max need ordering + Copy ---
#[inline(always)]
pub fn ct_min<T>(a: T, b: T) -> T
where
    T: ConstantTimeSelect + Ord + Copy,
{
    T::ct_select(a < b, a, b)
}

#[inline(always)]
pub fn ct_max<T>(a: T, b: T) -> T
where
    T: ConstantTimeSelect + Ord + Copy,
{
    T::ct_select(a > b, a, b)
}

// --- equality that returns bool ---
// Use the bool selector explicitly (result type is bool, not T)
#[inline(always)]
pub fn ct_eq<T>(a: T, b: T) -> bool
where
    T: PartialEq + Copy,
{
    <bool as ConstantTimeSelect>::ct_select(a == b, true, false)
}

pub trait ConstantTimeEq {
    fn ct_eq(self, other: Self) -> bool;
    const ZERO: Self;
}

pub fn ct_zero<T>(a: T) -> bool
where
    T: ConstantTimeEq + ConstantTimeSelect,
{
    let cond = a.ct_eq(T::ZERO);
    <bool as ConstantTimeSelect>::ct_select(cond, true, false)
}

/// Constant-time conditional swap
///
/// Swaps the contents of `a` and `b` if `condition` is true, otherwise leaves them unchanged.
/// This operation is performed in constant time regardless of the condition.
///
/// # Examples
///
/// ```
/// # #![feature(core_intrinsics)]
/// # use core::intrinsics::select::crypto::ct_swap;
/// let mut a = 10u32;
/// let mut b = 20u32;
///
/// ct_swap(&mut a, &mut b, true);
/// assert_eq!(a, 20);
/// assert_eq!(b, 10);
///
/// ct_swap(&mut a, &mut b, false);
/// assert_eq!(a, 20); // unchanged
/// assert_eq!(b, 10); // unchanged
/// ```
#[inline(always)]
pub fn ct_swap<T>(a: &mut T, b: &mut T, condition: bool)
where
    T: ConstantTimeSelect + Copy,
{
    let temp_a = *a;
    let temp_b = *b;
    *a = T::ct_select(condition, temp_b, temp_a);
    *b = T::ct_select(condition, temp_a, temp_b);
}

/// Constant-time mask generation
///
/// Returns all 1s if `condition` is true, all 0s otherwise.
/// Useful for bitwise operations that need to be constant-time.
///
/// # Examples
///
/// ```
/// # #![feature(core_intrinsics)]
/// # use core::intrinsics::select::crypto::ct_mask;
/// assert_eq!(ct_mask::<u32>(true), 0xFFFFFFFF);
/// assert_eq!(ct_mask::<u32>(false), 0x00000000);
/// ```
#[inline(always)]
pub fn ct_mask<T>(condition: bool) -> T
where
    T: ConstantTimeSelect + ConstantTimeEq + core::ops::Not<Output = T>,
{
    T::ct_select(condition, !T::ZERO, T::ZERO)
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

impl_constant_time_select!(*mut u8, ct_select_ptr);
impl_constant_time_select!(bool, ct_select_bool);