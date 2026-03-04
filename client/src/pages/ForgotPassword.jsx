import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { authAPI } from "../services/api";
import LoadingSpinner from "../Components/LoadingSpinner";
import {
  validatePassword as validate,
  PasswordStrengthBar,
  PasswordRequirements,
} from "../Components/PasswordValidation";
import toast from "react-hot-toast";
import { MessageSquare, Eye, EyeOff } from "lucide-react";

export default function ForgotPassword() {
  const [step, setStep] = useState(1);
  const [email, setEmail] = useState("");
  const [otp, setOtp] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [passwordFocused, setPasswordFocused] = useState(false);
  const [passwordValidation, setPasswordValidation] = useState(null);
  const [passwordStrength, setPasswordStrength] = useState("");
  const navigate = useNavigate();

  const handlePasswordChange = (e) => {
    const password = e.target.value;
    setNewPassword(password);
    const { validation, strength } = validate(password);
    setPasswordValidation(validation);
    setPasswordStrength(strength);
  };

  const handleRequestOTP = async (e) => {
    e.preventDefault();
    setIsLoading(true);

    try {
      const response = await authAPI.requestPasswordReset({ email });
      toast.success(response.data.message || "OTP sent to your email");
      setStep(2);
    } catch (error) {
      const errorMessage =
        error.response?.data?.error || "Failed to send OTP. Please try again.";
      toast.error(errorMessage);
    } finally {
      setIsLoading(false);
    }
  };

  const handleResetPassword = async (e) => {
    e.preventDefault();
    setIsLoading(true);

    try {
      await authAPI.verifyPasswordReset({
        email,
        otp,
        new_password: newPassword,
      });
      toast.success("Password reset successful!");
      setStep(3);
      setTimeout(() => navigate("/login"), 2000);
    } catch (error) {
      toast.error(error.response?.data?.error || "Failed to reset password");
    } finally {
      setIsLoading(false);
    }
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
              Reset Password
            </h1>
            <p className="text-dark-text-secondary text-sm">
              {step === 1
                ? "Enter your registered email address"
                : step === 2
                  ? "Check your email for the OTP code"
                  : "Password reset complete"}
            </p>
          </div>

          {step === 1 && (
            <form onSubmit={handleRequestOTP} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-dark-text mb-2">
                  Email Address
                </label>
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="input"
                  placeholder="Enter your email address"
                  required
                />
              </div>

              <button
                type="submit"
                disabled={isLoading}
                className="btn btn-primary w-full disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isLoading ? (
                  <LoadingSpinner text="Sending OTP..." />
                ) : (
                  "Send OTP"
                )}
              </button>
            </form>
          )}

          {step === 2 && (
            <form onSubmit={handleResetPassword} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-dark-text mb-2">
                  OTP Code
                </label>
                <input
                  type="text"
                  value={otp}
                  onChange={(e) => setOtp(e.target.value)}
                  className="input"
                  placeholder="Enter 6-digit OTP"
                  required
                  maxLength="6"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-dark-text mb-2">
                  New Password
                </label>
                <div className="relative">
                  <input
                    type={showPassword ? "text" : "password"}
                    value={newPassword}
                    onChange={handlePasswordChange}
                    onFocus={() => setPasswordFocused(true)}
                    onBlur={() =>
                      setTimeout(() => setPasswordFocused(false), 200)
                    }
                    className="w-full px-4 py-2 pr-10 bg-dark-bg text-dark-text border border-dark-border rounded-lg focus:outline-none focus:border-brand-primary"
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

                {newPassword && (
                  <PasswordStrengthBar strength={passwordStrength} />
                )}
                {passwordFocused && newPassword && (
                  <PasswordRequirements validation={passwordValidation} />
                )}
              </div>

              <button
                type="submit"
                disabled={isLoading}
                className="btn btn-primary w-full disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isLoading ? (
                  <LoadingSpinner text="Resetting Password..." />
                ) : (
                  "Reset Password"
                )}
              </button>
            </form>
          )}

          {step === 3 && (
            <div className="text-center">
              <div className="flex justify-center mb-4">
                <div className="relative">
                  <MessageSquare className="w-16 h-16 text-green-500 animate-pulse" />
                  <div className="absolute inset-0 bg-green-500 opacity-20 blur-xl rounded-full"></div>
                </div>
              </div>
              <h3 className="text-xl font-bold text-dark-text mb-2">
                Password Reset Successful!
              </h3>
              <p className="text-dark-text-secondary mb-4">
                Your password has been updated successfully.
              </p>
              <p className="text-sm text-dark-text-secondary mb-6">
                Redirecting to login page in 2 seconds...
              </p>
            </div>
          )}

          <div className="mt-6 text-center">
            <p className="text-dark-text-secondary text-sm">
              Remember your password?{" "}
              <Link
                to="/login"
                className="text-brand-primary hover:text-brand-primary-hover font-medium transition-colors"
              >
                Back to Login
              </Link>
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
