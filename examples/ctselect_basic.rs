//! Basic usage examples for ctselect intrinsic in Rust
//!
//! This module demonstrates the fundamental usage patterns of Rust's ct_select
//! intrinsics, which provide constant-time conditional selection to prevent
//! timing side-channel attacks.

#![feature(core_intrinsics)]
use std::intrinsics::{ct_select_i8, ct_select_i16, ct_select_i32, ct_select_i64};

/// Basic 32-bit integer selection
/// 
/// This function demonstrates the most common usage pattern for ct_select.
/// It returns `secret_a` if `condition` is true, otherwise `secret_b`.
/// The selection happens in constant time regardless of the condition value.
pub fn basic_select(condition: bool, secret_a: i32, secret_b: i32) -> i32 {
    return ct_select_i32(condition, secret_a, secret_b);
}

/// Example for all integer types
pub struct IntegerSelectionExamples;

impl IntegerSelectionExamples {
    pub fn select_i8(condition: bool, a: i8, b: i8) -> i8 {
        return ct_select_i8(condition, a, b);
    }
    
    pub fn select_i16(condition: bool, a: i16, b: i16) -> i16 {
        return ct_select_i16(condition, a, b);
    }
    
    pub fn select_i32(condition: bool, a: i32, b: i32) -> i32 {
        return ct_select_i32(condition, a, b);
    }
    
    pub fn select_i64(condition: bool, a: i64, b: i64) -> i64 {
        return ct_select_i64(condition, a, b);
    }
}

/// Constant-time minimum function
/// 
/// Returns the smaller of two values without branching.
/// This is useful in cryptographic contexts where timing must be constant.
pub fn ct_min_i32(a: i32, b: i32) -> i32 {
    return ct_select_i32(a <= b, a, b);
}

/// Constant-time maximum function
pub fn ct_max_i32(a: i32, b: i32) -> i32 {
    return ct_select_i32(a >= b, a, b);
}

/// Constant-time absolute value
/// 
/// Computes the absolute value without branching on the sign bit.
pub fn ct_abs_i32(value: i32) -> i32 {
    let is_negative = value < 0;
    return ct_select_i32(is_negative, -value, value);
}

/// Conditional negation
/// 
/// Negates the value if condition is true, otherwise returns it unchanged.
pub fn ct_conditional_negate(condition: bool, value: i32) -> i32 {
    return ct_select_i32(condition, -value, value);
}

/// Range clamping function
/// 
/// Clamps a value to be within [min_val, max_val] using constant-time operations.
pub fn ct_clamp_i32(value: i32, min_val: i32, max_val: i32) -> i32 {
    let clamped_min = ct_max_i32(value, min_val);
    return ct_min_i32(clamped_min, max_val);
}

/// Conditional arithmetic
/// 
/// Performs different arithmetic operations based on a condition.
pub fn ct_conditional_arithmetic(condition: bool, a: i32, b: i32) -> i32 {
    let add_result = a.wrapping_add(b);
    let sub_result = a.wrapping_sub(b);
    return ct_select_i32(condition, add_result, sub_result);
}

/// Sign extraction
/// 
/// Returns 1 if positive, -1 if negative, 0 if zero (constant time).
pub fn ct_signum_i32(value: i32) -> i32 {
    let is_positive = value > 0;
    let is_negative = value < 0;
    let positive_result = ct_select_i32(is_positive, 1, 0);
    return ct_select_i32(is_negative, -1, positive_result);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_select() {
        assert_eq!(basic_select(true, 42, 24), 42);
        assert_eq!(basic_select(false, 42, 24), 24);
    }

    #[test]
    fn test_integer_types() {
        assert_eq!(IntegerSelectionExamples::select_i8(true, 10, 20), 10);
        assert_eq!(IntegerSelectionExamples::select_i16(false, 100, 200), 200);
        assert_eq!(IntegerSelectionExamples::select_i32(true, 1000, 2000), 1000);
        assert_eq!(IntegerSelectionExamples::select_i64(false, 10000, 20000), 20000);
    }

    #[test]
    fn test_ct_min_max() {
        assert_eq!(ct_min_i32(5, 3), 3);
        assert_eq!(ct_min_i32(3, 5), 3);
        assert_eq!(ct_max_i32(5, 3), 5);
        assert_eq!(ct_max_i32(3, 5), 5);
    }

    #[test]
    fn test_ct_abs() {
        assert_eq!(ct_abs_i32(42), 42);
        assert_eq!(ct_abs_i32(-42), 42);
        assert_eq!(ct_abs_i32(0), 0);
    }

    #[test]
    fn test_conditional_negate() {
        assert_eq!(ct_conditional_negate(true, 42), -42);
        assert_eq!(ct_conditional_negate(false, 42), 42);
        assert_eq!(ct_conditional_negate(true, -42), 42);
    }

    #[test]
    fn test_ct_clamp() {
        assert_eq!(ct_clamp_i32(5, 0, 10), 5);   // Within range
        assert_eq!(ct_clamp_i32(-5, 0, 10), 0);  // Below min
        assert_eq!(ct_clamp_i32(15, 0, 10), 10); // Above max
    }

    #[test]
    fn test_conditional_arithmetic() {
        assert_eq!(ct_conditional_arithmetic(true, 10, 5), 15);  // Addition
        assert_eq!(ct_conditional_arithmetic(false, 10, 5), 5);  // Subtraction
    }

    #[test]
    fn test_ct_signum() {
        assert_eq!(ct_signum_i32(42), 1);
        assert_eq!(ct_signum_i32(-42), -1);
        assert_eq!(ct_signum_i32(0), 0);
    }
}

fn main() {
    println!("=== Rust ctselect Basic Examples ===\n");
    
    // Basic selection
    println!("Basic selection:");
    println!("  select(true, 42, 24) = {}", basic_select(true, 42, 24));
    println!("  select(false, 42, 24) = {}", basic_select(false, 42, 24));
    
    // Integer types
    println!("\nDifferent integer types:");
    println!("  i8: select(true, 10, 20) = {}", IntegerSelectionExamples::select_i8(true, 10, 20));
    println!("  i16: select(false, 100, 200) = {}", IntegerSelectionExamples::select_i16(false, 100, 200));
    println!("  i32: select(true, 1000, 2000) = {}", IntegerSelectionExamples::select_i32(true, 1000, 2000));
    println!("  i64: select(false, 10000, 20000) = {}", IntegerSelectionExamples::select_i64(false, 10000, 20000));
    
    // Min/Max
    println!("\nConstant-time min/max:");
    println!("  ct_min(5, 3) = {}", ct_min_i32(5, 3));
    println!("  ct_max(5, 3) = {}", ct_max_i32(5, 3));
    
    // Absolute value
    println!("\nConstant-time absolute value:");
    println!("  ct_abs(42) = {}", ct_abs_i32(42));
    println!("  ct_abs(-42) = {}", ct_abs_i32(-42));
    
    // Conditional negation
    println!("\nConditional negation:");
    println!("  ct_conditional_negate(true, 42) = {}", ct_conditional_negate(true, 42));
    println!("  ct_conditional_negate(false, 42) = {}", ct_conditional_negate(false, 42));
    
    // Clamping
    println!("\nConstant-time clamping:");
    println!("  ct_clamp(5, 0, 10) = {}", ct_clamp_i32(5, 0, 10));
    println!("  ct_clamp(-5, 0, 10) = {}", ct_clamp_i32(-5, 0, 10));
    println!("  ct_clamp(15, 0, 10) = {}", ct_clamp_i32(15, 0, 10));
    
    // Sign function
    println!("\nConstant-time sign function:");
    println!("  ct_signum(42) = {}", ct_signum_i32(42));
    println!("  ct_signum(-42) = {}", ct_signum_i32(-42));
    println!("  ct_signum(0) = {}", ct_signum_i32(0));
}
