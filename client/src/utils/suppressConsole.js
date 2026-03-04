/**
 * Suppress specific console warnings and errors in production
 */

// Store original console methods
const originalError = console.error;
const originalWarn = console.warn;

// Patterns to suppress
const suppressPatterns = [
  /Failed to load resource.*401/i,
  /Failed to load resource.*403/i,
  /GSI_LOGGER/i,
  /FedCM/i,
  /fedcm-migration/i,
  /Google One Tap/i,
  /credential_button_library/i,
  /accounts\.google\.com/i,
  /Unauthorized/i,
];

// Override console.error
console.error = (...args) => {
  const message = args.join(" ");
  const shouldSuppress = suppressPatterns.some((pattern) =>
    pattern.test(message),
  );

  if (!shouldSuppress) {
    originalError.apply(console, args);
  }
};

// Override console.warn
console.warn = (...args) => {
  const message = args.join(" ");
  const shouldSuppress = suppressPatterns.some((pattern) =>
    pattern.test(message),
  );

  if (!shouldSuppress) {
    originalWarn.apply(console, args);
  }
};

// Suppress unhandled promise rejections for specific errors
window.addEventListener("unhandledrejection", (event) => {
  const message = event.reason?.message || event.reason?.toString() || "";
  const shouldSuppress = suppressPatterns.some((pattern) =>
    pattern.test(message),
  );

  if (shouldSuppress) {
    event.preventDefault();
  }
});

export default {};
