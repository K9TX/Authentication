import { useState, useCallback } from "react";
import { Link, useNavigate } from "react-router-dom";
import { GoogleLogin } from "@react-oauth/google";
import { useAuthStore } from "../stores/authStore";
import { authAPI, getErrorMessage } from "../services/api";
import { useGoogleOneTap } from "../hooks/useGoogleOneTap";
import LoadingSpinner from "../Components/LoadingSpinner";
import toast from "react-hot-toast";
import { MessageSquare, Eye, EyeOff } from "lucide-react";

export default function Login() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState("");
  const [mfaRequired, setMfaRequired] = useState(false);
  const [mfaCode, setMfaCode] = useState("");
  const { login, setUser, setIsAuthenticated } = useAuthStore();
  const navigate = useNavigate();

  // Shared handler: Google login returns mfa_required → switch to MFA form
  const handleGoogleMfaRequired = useCallback((mfaEmail) => {
    setEmail(mfaEmail);
    setMfaRequired(true);
    toast("MFA verification required", { icon: "🔐" });
  }, []);

  // Google One Tap auto-popup — MFA-aware
  useGoogleOneTap({
    disabled: false,
    context: "signin",
    onMfaRequired: handleGoogleMfaRequired,
  });

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (isLoading) return;

    setIsLoading(true);
    setError("");

    const result = await login({ email, password });
    setIsLoading(false);

    if (!result) {
      const msg = "No response from server";
      setError(msg);
      toast.error(msg);
      return;
    }

    // MFA required - show MFA input
    if (result.mfa_required) {
      setMfaRequired(true);
      return;
    }

    // Login successful
    if (result.success) {
      toast.success("Welcome back!");
      setTimeout(() => navigate("/dashboard"), 100);
      return;
    }

    // Login failed
    if (result.error) {
      setError(result.error);
      toast.error(result.error);
    }
  };

  const handleMfaSubmit = async (e) => {
    e.preventDefault();
    setIsLoading(true);
    setError("");

    try {
      const response = await authAPI.mfaVerifyLogin({
        email,
        mfa_code: mfaCode,
      });

      const { user } = response.data;
      setUser(user);
      setIsAuthenticated(true);

      toast.success("Login successful!");
      navigate("/dashboard");
    } catch (err) {
      const errorMsg = getErrorMessage(err);
      setError(errorMsg);
      toast.error(errorMsg);
    } finally {
      setIsLoading(false);
    }
  };

  const handleGoogleSuccess = async (credentialResponse) => {
    setIsLoading(true);
    setError("");

    try {
      const response = await authAPI.googleLogin(credentialResponse.credential);

      // MFA required — Google login doesn't bypass TOTP
      if (response.data.mfa_required) {
        setEmail(response.data.email);
        setMfaRequired(true);
        toast("MFA verification required", { icon: "🔐" });
        return;
      }

      setUser(response.data.user);
      setIsAuthenticated(true);
      toast.success("Google login successful!");
      navigate("/dashboard");
    } catch (error) {
      const errorMsg = getErrorMessage(error);
      setError(errorMsg);
      toast.error(errorMsg);
    } finally {
      setIsLoading(false);
    }
  };

  const handleGoogleError = () => {
    toast.error("Google login failed");
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-dark-bg via-dark-surface to-dark-bg px-4 relative overflow-hidden">
      {/* Animated Background */}
      <div className="absolute inset-0 overflow-hidden">
        <div className="absolute -top-40 -right-40 w-80 h-80 bg-brand-primary opacity-10 rounded-full blur-3xl animate-pulse-slow"></div>
        <div
          className="absolute -bottom-40 -left-40 w-80 h-80 bg-brand-secondary opacity-10 rounded-full blur-3xl animate-pulse-slow"
          style={{ animationDelay: "1s" }}
        ></div>
      </div>

      <div className="max-w-md w-full relative z-10">
        <div className="bg-dark-card rounded-2xl shadow-dark-xl p-8 border border-dark-border backdrop-blur-sm">
          <div className="text-center mb-8">
            <div className="flex justify-center mb-4">
              <div className="relative">
                <MessageSquare className="w-16 h-16 text-brand-primary animate-pulse" />
                <div className="absolute inset-0 bg-brand-primary opacity-20 blur-xl rounded-full"></div>
              </div>
            </div>
            <h1 className="text-4xl font-bold gradient-text mb-2">
              SecureAuth
            </h1>
            <p className="text-dark-text-secondary">
              {mfaRequired ? "Enter MFA Code" : "Sign in to your account"}
            </p>
          </div>

          {/* MFA Code Form */}
          {mfaRequired ? (
            <form onSubmit={handleMfaSubmit} className="space-y-6">
              {error && (
                <div className="bg-brand-error/10 border border-brand-error/30 text-brand-error px-4 py-3 rounded-lg text-sm backdrop-blur-sm animate-slide-down">
                  {error}
                </div>
              )}

              <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 mb-4">
                <p className="text-sm text-blue-800 text-center">
                  Open Google Authenticator app and enter the 6-digit code
                </p>
              </div>

              <div>
                <label className="block text-sm font-medium text-dark-text mb-2">
                  MFA Code
                </label>
                <input
                  type="text"
                  value={mfaCode}
                  onChange={(e) =>
                    setMfaCode(e.target.value.replace(/\D/g, "").slice(0, 6))
                  }
                  className="input text-center text-2xl tracking-widest"
                  placeholder="000000"
                  maxLength={6}
                  required
                  autoFocus
                />
                <p className="text-xs text-dark-text-secondary mt-2 text-center">
                  Enter the 6-digit code from Google Authenticator
                </p>
              </div>

              <button
                type="submit"
                disabled={isLoading || mfaCode.length !== 6}
                className="btn btn-primary w-full disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isLoading ? (
                  <LoadingSpinner text="Verifying..." />
                ) : (
                  "Verify & Sign In"
                )}
              </button>

              <button
                type="button"
                onClick={() => {
                  setMfaRequired(false);
                  setMfaCode("");
                  setError("");
                }}
                className="w-full text-sm text-dark-text-secondary hover:text-dark-text transition-colors"
              >
                ← Back to login
              </button>
            </form>
          ) : (
            /* Regular Login Form */
            <form onSubmit={handleSubmit} className="space-y-6">
              {/* Error Message */}
              {error && (
                <div className="bg-brand-error/10 border border-brand-error/30 text-brand-error px-4 py-3 rounded-lg text-sm backdrop-blur-sm animate-slide-down">
                  {error}
                </div>
              )}

              <div>
                <label className="block text-sm font-medium text-dark-text mb-2">
                  Email
                </label>
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="input"
                  placeholder="Enter your email"
                  required
                />
              </div>

              <div>
                <div className="flex justify-between items-center mb-2">
                  <label className="block text-sm font-medium text-dark-text">
                    Password
                  </label>
                  <Link
                    to="/forgot-password"
                    className="text-sm text-brand-primary hover:text-brand-primary-hover transition-colors"
                  >
                    Forgot password?
                  </Link>
                </div>
                <div className="relative">
                  <input
                    type={showPassword ? "text" : "password"}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="input pr-10"
                    placeholder="Enter your password"
                    required
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-dark-text-secondary hover:text-dark-text transition-colors"
                    tabIndex={-1}
                  >
                    {showPassword ? (
                      <EyeOff className="w-5 h-5" />
                    ) : (
                      <Eye className="w-5 h-5" />
                    )}
                  </button>
                </div>
              </div>

              <button
                type="submit"
                disabled={isLoading}
                className="btn btn-primary w-full disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isLoading ? (
                  <LoadingSpinner text="Signing in..." />
                ) : (
                  "Sign In"
                )}
              </button>
            </form>
          )}

          {/* Google Sign-In - Only show when not in MFA mode */}
          {!mfaRequired && (
            <>
              <div className="mt-6">
                <div className="relative mb-6">
                  <div className="absolute inset-0 flex items-center">
                    <div className="w-full border-t border-dark-border"></div>
                  </div>
                  <div className="relative flex justify-center text-sm">
                    <span className="px-3 bg-dark-card text-dark-text-secondary">
                      Or continue with
                    </span>
                  </div>
                </div>

                <div className="w-full flex justify-center">
                  <GoogleLogin
                    onSuccess={handleGoogleSuccess}
                    onError={handleGoogleError}
                    theme="filled_black"
                    size="large"
                    text="continue_with"
                    shape="rectangular"
                    useOneTap={false}
                  />
                </div>
              </div>

              <div className="mt-6 text-center">
                <p className="text-dark-text-secondary text-sm">
                  Don't have an account?{" "}
                  <Link
                    to="/register"
                    className="text-brand-primary hover:text-brand-primary-hover font-medium transition-colors"
                  >
                    Create Account
                  </Link>
                </p>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
