import { useState, useCallback } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useAuthStore } from "../stores/authStore";
import { useGoogleOneTap } from "../hooks/useGoogleOneTap";
import LoadingSpinner from "../Components/LoadingSpinner";
import {
  validatePassword,
  PasswordStrengthBar,
  PasswordRequirements,
} from "../Components/PasswordValidation";
import toast from "react-hot-toast";
import { MessageSquare, Check, X, Eye, EyeOff } from "lucide-react";

export default function Register() {
  const navigate = useNavigate();

  // Google One Tap — if a returning user with MFA signs up, redirect to login
  const handleGoogleMfaRequired = useCallback(() => {
    toast("Account requires MFA. Redirecting to login…", { icon: "🔐" });
    navigate("/login");
  }, [navigate]);

  useGoogleOneTap({
    disabled: false,
    context: "signup",
    onMfaRequired: handleGoogleMfaRequired,
  });
  const [formData, setFormData] = useState({
    username: "",
    email: "",
    password: "",
    password_confirm: "",
    first_name: "",
    last_name: "",
  });
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [showPasswordConfirm, setShowPasswordConfirm] = useState(false);
  const [passwordFocused, setPasswordFocused] = useState(false);
  const [passwordValidation, setPasswordValidation] = useState(null);
  const [passwordStrength, setPasswordStrength] = useState("");
  const { register } = useAuthStore();

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData({ ...formData, [name]: value });

    if (name === "password") {
      const { validation, strength } = validatePassword(value);
      setPasswordValidation(validation);
      setPasswordStrength(strength);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");

    if (formData.password !== formData.password_confirm) {
      const errorMsg =
        "Passwords do not match. Please make sure both passwords are identical.";
      setError(errorMsg);
      toast.error(errorMsg);
      return;
    }

    setIsLoading(true);
    const result = await register(formData);
    setIsLoading(false);

    if (result.success) {
      const message =
        result.data?.message ||
        "Registration successful! Check your email for verification.";
      toast.success(message);
      navigate("/verify-email", {
        state: { email: formData.email },
        replace: true,
      });
      return;
    }

    // Handle registration errors
    const errors = result.error;
    let errorMsg = "Registration failed. Please try again.";

    if (typeof errors === "object") {
      errorMsg = Object.values(errors)
        .map((err) => (Array.isArray(err) ? err[0] : err))
        .join(", ");
      Object.values(errors).forEach((err) => {
        toast.error(Array.isArray(err) ? err[0] : err);
      });
    } else {
      errorMsg = errors;
      toast.error(errors);

      // Redirect to verify page if account already exists
      if (
        errorMsg.toLowerCase().includes("already exists") ||
        errorMsg.toLowerCase().includes("account exists")
      ) {
        setTimeout(() => {
          navigate("/verify-email", {
            state: { email: formData.email },
            replace: true,
          });
        }, 2000);
      }
    }
    setError(errorMsg);
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-dark-bg via-dark-surface to-dark-bg px-4 py-8 relative overflow-hidden">
      {/* Animated Background */}
      <div className="absolute inset-0 overflow-hidden">
        <div className="absolute top-20 right-20 w-80 h-80 bg-brand-secondary opacity-10 rounded-full blur-3xl animate-pulse-slow"></div>
        <div
          className="absolute bottom-20 left-20 w-80 h-80 bg-brand-primary opacity-10 rounded-full blur-3xl animate-pulse-slow"
          style={{ animationDelay: "1.5s" }}
        ></div>
      </div>

      <div className="max-w-md w-full relative z-10">
        <div className="bg-dark-card rounded-2xl shadow-dark-xl p-6 border border-dark-border backdrop-blur-sm">
          <div className="text-center mb-6">
            <div className="flex justify-center mb-3">
              <div className="relative">
                <MessageSquare className="w-14 h-14 text-brand-secondary animate-pulse" />
                <div className="absolute inset-0 bg-brand-secondary opacity-20 blur-xl rounded-full"></div>
              </div>
            </div>
            <h1 className="text-3xl font-bold gradient-text mb-1">
              SecureAuth
            </h1>
            <p className="text-dark-text-secondary text-sm">
              Create your account
            </p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-3">
            {/* Error Message */}
            {error && (
              <div className="bg-brand-error/10 border border-brand-error/30 text-brand-error px-3 py-2 rounded-lg text-xs backdrop-blur-sm animate-slide-down">
                {error}
              </div>
            )}

            <div>
              <label className="block text-sm font-medium text-dark-text mb-2">
                Username
              </label>
              <input
                type="text"
                name="username"
                value={formData.username}
                onChange={handleChange}
                className="input"
                placeholder="Choose a username"
                required
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-dark-text mb-2">
                Email
              </label>
              <input
                type="email"
                name="email"
                value={formData.email}
                onChange={handleChange}
                className="input"
                placeholder="your@email.com"
                required
              />
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-dark-text mb-2">
                  First Name
                </label>
                <input
                  type="text"
                  name="first_name"
                  value={formData.first_name}
                  onChange={handleChange}
                  className="input"
                  placeholder="First name"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-dark-text mb-2">
                  Last Name
                </label>
                <input
                  type="text"
                  name="last_name"
                  value={formData.last_name}
                  onChange={handleChange}
                  className="input"
                  placeholder="Last name"
                />
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium text-dark-text mb-2">
                Password
              </label>
              <div className="relative">
                <input
                  type={showPassword ? "text" : "password"}
                  name="password"
                  value={formData.password}
                  onChange={handleChange}
                  onFocus={() => setPasswordFocused(true)}
                  onBlur={() =>
                    setTimeout(() => setPasswordFocused(false), 200)
                  }
                  className="input pr-10"
                  placeholder="Create a strong password"
                  required
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-dark-text-secondary hover:text-dark-text"
                >
                  {showPassword ? (
                    <EyeOff className="w-5 h-5" />
                  ) : (
                    <Eye className="w-5 h-5" />
                  )}
                </button>
              </div>

              {formData.password && (
                <PasswordStrengthBar strength={passwordStrength} />
              )}
              {passwordFocused && formData.password && (
                <PasswordRequirements validation={passwordValidation} />
              )}
            </div>

            <div>
              <label className="block text-sm font-medium text-dark-text mb-2">
                Confirm Password
              </label>
              <div className="relative">
                <input
                  type={showPasswordConfirm ? "text" : "password"}
                  name="password_confirm"
                  value={formData.password_confirm}
                  onChange={handleChange}
                  className="input pr-10"
                  placeholder="Confirm your password"
                  required
                />
                <button
                  type="button"
                  onClick={() => setShowPasswordConfirm(!showPasswordConfirm)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-dark-text-secondary hover:text-dark-text"
                >
                  {showPasswordConfirm ? (
                    <EyeOff className="w-5 h-5" />
                  ) : (
                    <Eye className="w-5 h-5" />
                  )}
                </button>
              </div>
              {formData.password_confirm &&
                formData.password !== formData.password_confirm && (
                  <p className="text-red-500 text-xs mt-1 flex items-center gap-1">
                    <X className="w-3 h-3" />
                    Passwords do not match
                  </p>
                )}
              {formData.password_confirm &&
                formData.password === formData.password_confirm && (
                  <p className="text-green-500 text-xs mt-1 flex items-center gap-1">
                    <Check className="w-3 h-3" />
                    Passwords match
                  </p>
                )}
            </div>

            <button
              type="submit"
              disabled={isLoading}
              className="btn btn-primary w-full disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isLoading ? (
                <LoadingSpinner text="Creating account..." />
              ) : (
                "Create Account"
              )}
            </button>
          </form>

          <div className="mt-6 text-center">
            <p className="text-dark-text-secondary text-sm">
              Already have an account?{" "}
              <Link
                to="/login"
                className="text-brand-primary hover:text-brand-primary-hover font-medium transition-colors"
              >
                Sign In
              </Link>
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
