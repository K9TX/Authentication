import { useState, useEffect } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { useAuthStore } from "../stores/authStore";
import { authAPI } from "../services/api";
import toast from "react-hot-toast";
import { Clock } from "lucide-react";

export default function VerifyEmail() {
  const [otpCode, setOtpCode] = useState(["", "", "", "", "", ""]);
  const [isLoading, setIsLoading] = useState(false);
  const [isResending, setIsResending] = useState(false);
  const [resendTimer, setResendTimer] = useState(60); // Start with 60 seconds on page load
  const navigate = useNavigate();
  const location = useLocation();
  const email = location.state?.email;
  const { updateUser, user } = useAuthStore();

  // Timer countdown effect
  useEffect(() => {
    let interval;
    if (resendTimer > 0) {
      interval = setInterval(() => {
        setResendTimer((prev) => prev - 1);
      }, 1000);
    }
    return () => clearInterval(interval);
  }, [resendTimer]);

  useEffect(() => {
    // Redirect if already verified
    if (user?.is_verified) {
      navigate("/dashboard", { replace: true });
      return;
    }

    // Redirect if no email provided
    if (!email) {
      toast.error("Please register first");
      navigate("/register", { replace: true });
    }
  }, [email, navigate, user]);

  const handleOtpChange = (index, value) => {
    // Only allow numbers
    if (value && !/^\d$/.test(value)) return;

    const newOtp = [...otpCode];
    newOtp[index] = value;
    setOtpCode(newOtp);

    // Auto-focus next input
    if (value && index < 5) {
      const nextInput = document.getElementById(`otp-${index + 1}`);
      if (nextInput) nextInput.focus();
    }
  };

  const handleKeyDown = (index, e) => {
    // Handle backspace
    if (e.key === "Backspace" && !otpCode[index] && index > 0) {
      const prevInput = document.getElementById(`otp-${index - 1}`);
      if (prevInput) prevInput.focus();
    }
  };

  const handlePaste = (e) => {
    e.preventDefault();
    const pastedData = e.clipboardData.getData("text").slice(0, 6);

    if (!/^\d+$/.test(pastedData)) {
      toast.error("Please paste only numbers");
      return;
    }

    const newOtp = pastedData.split("").concat(Array(6).fill("")).slice(0, 6);
    setOtpCode(newOtp);

    // Focus last filled input or first empty
    const focusIndex = Math.min(pastedData.length, 5);
    const input = document.getElementById(`otp-${focusIndex}`);
    if (input) input.focus();
  };

  const handleVerify = async (e) => {
    e.preventDefault();

    const code = otpCode.join("");
    if (code.length !== 6) {
      toast.error("Please enter complete OTP code");
      return;
    }

    setIsLoading(true);
    try {
      const response = await authAPI.verifyEmailOTP({ email, code });
      toast.success(response.data.message || "Email verified successfully!");

      // Update user state with verified status
      if (response.data.user) {
        updateUser(response.data.user);
      }

      setTimeout(() => navigate("/dashboard", { replace: true }), 500);
    } catch (error) {
      const errorMessage = error.response?.data?.error || "Verification failed";

      // Show appropriate error message
      if (
        errorMessage.toLowerCase().includes("expired") ||
        errorMessage.toLowerCase().includes("invalid") ||
        errorMessage.toLowerCase().includes("attempts")
      ) {
        toast.error(`${errorMessage}. Please request a new code.`, {
          duration: 4000,
        });
      } else {
        toast.error(errorMessage);
      }

      // Clear OTP and refocus
      setOtpCode(["", "", "", "", "", ""]);
      document.getElementById("otp-0")?.focus();
    } finally {
      setIsLoading(false);
    }
  };

  const handleResend = async () => {
    if (resendTimer > 0) return;

    setIsResending(true);
    try {
      await authAPI.resendVerification({ email });
      toast.success("Verification code sent to your email");
      setOtpCode(["", "", "", "", "", ""]);
      document.getElementById("otp-0")?.focus();
      setResendTimer(60);
    } catch (error) {
      toast.error("Failed to resend code");
    } finally {
      setIsResending(false);
    }
  };

  if (!email) {
    return null;
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-dark-bg py-8">
      <div className="bg-dark-surface p-8 rounded-lg shadow-lg w-full max-w-md">
        <div className="text-center mb-8">
          <div className="mx-auto w-16 h-16 bg-brand-primary/10 rounded-full flex items-center justify-center mb-4">
            <svg
              className="w-8 h-8 text-brand-primary"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"
              />
            </svg>
          </div>
          <h2 className="text-3xl font-bold text-dark-text mb-2">
            Verify Your Email
          </h2>
          <p className="text-dark-text-secondary">
            We've sent a 6-digit code to
          </p>
          <p className="text-brand-primary font-medium mt-1">{email}</p>
        </div>

        <form onSubmit={handleVerify} className="space-y-6">
          <div>
            <label className="block text-dark-text mb-3 text-center">
              Enter Verification Code
            </label>
            <div className="flex gap-2 justify-center">
              {otpCode.map((digit, index) => (
                <input
                  key={index}
                  id={`otp-${index}`}
                  type="text"
                  maxLength={1}
                  value={digit}
                  onChange={(e) => handleOtpChange(index, e.target.value)}
                  onKeyDown={(e) => handleKeyDown(index, e)}
                  onPaste={handlePaste}
                  className="w-12 h-14 text-center text-2xl font-bold bg-dark-bg text-dark-text border-2 border-dark-border rounded-lg focus:outline-none focus:border-brand-primary transition-colors"
                  disabled={isLoading}
                />
              ))}
            </div>
          </div>

          <button
            type="submit"
            disabled={isLoading || otpCode.join("").length !== 6}
            className="w-full bg-brand-primary text-white py-3 rounded-lg hover:bg-blue-600 disabled:opacity-50 disabled:cursor-not-allowed font-medium transition-colors"
          >
            {isLoading ? "Verifying..." : "Verify Email"}
          </button>
        </form>

        <div className="mt-6 text-center">
          <p className="text-dark-text-secondary mb-2">
            Didn't receive the code?
          </p>
          {resendTimer > 0 ? (
            <div className="flex items-center justify-center gap-2 text-dark-text-secondary">
              <Clock className="w-4 h-4" />
              <span className="text-sm">
                Resend code in{" "}
                <span className="text-brand-primary font-semibold">
                  {resendTimer}s
                </span>
              </span>
            </div>
          ) : (
            <button
              onClick={handleResend}
              disabled={isResending}
              className="text-brand-primary hover:underline font-medium disabled:opacity-50"
            >
              {isResending ? "Sending..." : "Resend Code"}
            </button>
          )}
        </div>

        <div className="mt-6 text-center">
          <button
            onClick={() => {
              // Clear auth state and go to login instead
              navigate("/login", { replace: true });
            }}
            className="text-dark-text-secondary hover:text-dark-text text-sm"
          >
            ← Back to Login
          </button>
        </div>
      </div>
    </div>
  );
}
