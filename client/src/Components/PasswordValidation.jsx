import { Check, X } from "lucide-react";

/**
 * Shared password validation logic + UI
 * Extracted from Register.jsx and ForgotPassword.jsx to eliminate duplication
 */

// Password validation rules
export const PASSWORD_RULES = {
  length: {
    test: (p) => p.length >= 8 && p.length <= 20,
    label: "8-20 Characters",
  },
  capital: {
    test: (p) => /[A-Z]/.test(p),
    label: "At least one capital letter",
  },
  number: { test: (p) => /[0-9]/.test(p), label: "At least one number" },
  noSpaces: { test: (p) => !/\s/.test(p), label: "No spaces" },
};

/**
 * Validate password and return { validation, strength }
 */
export function validatePassword(password) {
  const validation = {};
  for (const [key, rule] of Object.entries(PASSWORD_RULES)) {
    validation[key] = rule.test(password);
  }

  const validCount = Object.values(validation).filter(Boolean).length;
  let strength = "weak";
  if (validCount === 4) strength = "strong";
  else if (validCount >= 2) strength = "medium";

  return { validation, strength };
}

/**
 * Password strength bar component
 */
export function PasswordStrengthBar({ strength }) {
  if (!strength) return null;

  const config = {
    strong: {
      width: "w-full",
      color: "bg-green-500",
      textColor: "text-green-500",
    },
    medium: {
      width: "w-2/3",
      color: "bg-yellow-500",
      textColor: "text-yellow-500",
    },
    weak: { width: "w-1/3", color: "bg-red-500", textColor: "text-red-500" },
  };

  const { width, color, textColor } = config[strength];

  return (
    <div className="mt-2">
      <div className="flex items-center gap-2 mb-2">
        <div className="flex-1 h-2 bg-dark-bg rounded-full overflow-hidden">
          <div
            className={`h-full transition-all duration-300 ${width} ${color}`}
          />
        </div>
        <span className={`text-xs font-medium ${textColor}`}>{strength}</span>
      </div>
    </div>
  );
}

/**
 * Password requirements tooltip component
 */
export function PasswordRequirements({ validation }) {
  if (!validation) return null;

  return (
    <div className="mt-2 p-3 bg-dark-surface border border-dark-border rounded-lg text-sm animate-slide-down">
      <p className="text-dark-text font-medium mb-2">Password must include:</p>
      <div className="space-y-1">
        {Object.entries(PASSWORD_RULES).map(([key, rule]) => {
          const passed = validation[key];
          return (
            <div key={key} className="flex items-center gap-2">
              {passed ? (
                <Check className="w-4 h-4 text-green-500" />
              ) : (
                <X className="w-4 h-4 text-red-500" />
              )}
              <span className={passed ? "text-green-500" : "text-red-500"}>
                {rule.label}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
