/**
 * Authentication Page (Week 4: RBAC)
 *
 * Login and registration using RBAC backend
 */

import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "@/contexts/AuthContext";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { useToast } from "@/hooks/use-toast";
import { User, Shield, Briefcase } from "lucide-react";
import cyberBearLogo from "@/assets/cyber-bear-logo.png";
import { z } from "zod";

const loginSchema = z.object({
  email: z.string().email("Invalid email address").max(255, "Email too long"),
  password: z.string().min(1, "Password is required").max(100, "Password too long"),
});

const registerSchema = z.object({
  email: z.string().email("Invalid email address").max(255, "Email too long"),
  password: z.string().min(8, "Password must be at least 8 characters").max(100, "Password too long"),
  username: z.string().min(3, "Username must be at least 3 characters").max(50, "Username too long"),
  organizationName: z.string().min(1, "Organization name is required").max(100, "Organization name too long"),
});

type Role = "analyst" | "developer" | "executive";

const Auth = () => {
  const navigate = useNavigate();
  const { toast } = useToast();
  const { user, login, register, isLoading: authLoading } = useAuth();

  const [isLogin, setIsLogin] = useState(true);
  const [loading, setLoading] = useState(false);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [username, setUsername] = useState("");
  const [organizationName, setOrganizationName] = useState("");
  const [selectedRole, setSelectedRole] = useState<Role | null>(null);
  const [showForgotPassword, setShowForgotPassword] = useState(false);

  // Redirect if already logged in
  useEffect(() => {
    if (user && !authLoading) {
      navigate("/dashboard");
    }
  }, [user, authLoading, navigate]);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();

    // Validate input
    const validation = loginSchema.safeParse({ email, password });
    if (!validation.success) {
      toast({
        title: "Validation Error",
        description: validation.error.errors[0].message,
        variant: "destructive",
      });
      return;
    }

    setLoading(true);
    try {
      await login(validation.data.email, validation.data.password);
    } catch (error) {
      // Error handling done in AuthContext
    } finally {
      setLoading(false);
    }
  };

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();

    // Validate input
    const validation = registerSchema.safeParse({
      email,
      password,
      username,
      organizationName
    });
    if (!validation.success) {
      toast({
        title: "Validation Error",
        description: validation.error.errors[0].message,
        variant: "destructive",
      });
      return;
    }

    setLoading(true);
    try {
      await register(
        validation.data.email,
        validation.data.password,
        validation.data.username,
        validation.data.organizationName
      );
    } catch (error) {
      // Error handling done in AuthContext
    } finally {
      setLoading(false);
    }
  };

  const handlePasswordReset = async (e: React.FormEvent) => {
    e.preventDefault();

    toast({
      title: "Password Reset",
      description: "Password reset functionality will be available soon. Please contact support.",
    });
  };

  const roles = [
    {
      id: "analyst" as Role,
      icon: Shield,
      label: "Analyst",
      description: "Analyze and triage vulnerabilities",
    },
    {
      id: "developer" as Role,
      icon: User,
      label: "Developer",
      description: "Build and test APIs",
    },
    {
      id: "executive" as Role,
      icon: Briefcase,
      label: "Executive",
      description: "Monitor compliance and risk",
    },
  ];

  return (
    <div className="min-h-screen bg-gradient-to-br from-primary via-primary/95 to-primary/90 flex items-center justify-center p-6">
      <Card className="w-full max-w-md">
        <CardHeader className="text-center">
          <div className="flex justify-center mb-4">
            <img src={cyberBearLogo} alt="VentiAPI" className="w-20 h-20" />
          </div>
          <CardTitle className="text-2xl">
            {showForgotPassword ? "Reset Password" : isLogin ? "Welcome Back" : "Create Account"}
          </CardTitle>
          <CardDescription>
            {showForgotPassword
              ? "Enter your email to receive a password reset link"
              : isLogin ? "Sign in to access your dashboard" : "Join VentiAPI to secure your APIs"}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {showForgotPassword ? (
            <form onSubmit={handlePasswordReset} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="email">Email</Label>
                <Input
                  id="email"
                  type="email"
                  placeholder="name@company.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                  maxLength={255}
                />
              </div>

              <Button type="submit" className="w-full" disabled={loading}>
                {loading ? "Sending..." : "Send Reset Link"}
              </Button>

              <div className="text-center text-sm">
                <button
                  type="button"
                  onClick={() => setShowForgotPassword(false)}
                  className="text-primary font-medium hover:underline"
                >
                  Back to sign in
                </button>
              </div>
            </form>
          ) : (
          <form onSubmit={isLogin ? handleLogin : handleRegister} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="email">Email</Label>
              <Input
                id="email"
                type="email"
                placeholder="name@company.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                maxLength={255}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="password">Password</Label>
              <Input
                id="password"
                type="password"
                placeholder="••••••••"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                minLength={isLogin ? 1 : 8}
                maxLength={100}
              />
            </div>

            {!isLogin && (
              <>
                <div className="space-y-2">
                  <Label htmlFor="username">Username</Label>
                  <Input
                    id="username"
                    type="text"
                    placeholder="johndoe"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    required
                    minLength={3}
                    maxLength={50}
                  />
                </div>

                <div className="space-y-2">
                  <Label htmlFor="organizationName">Organization Name</Label>
                  <Input
                    id="organizationName"
                    type="text"
                    placeholder="Acme Inc."
                    value={organizationName}
                    onChange={(e) => setOrganizationName(e.target.value)}
                    required
                    maxLength={100}
                  />
                </div>

                <div className="space-y-2">
                  <Label>Select Your Role (Optional)</Label>
                  <div className="grid grid-cols-1 gap-2">
                    {roles.map((role) => (
                      <button
                        key={role.id}
                        type="button"
                        onClick={() => setSelectedRole(role.id)}
                        className={`flex items-start gap-3 p-3 rounded-lg border-2 transition-all text-left ${
                          selectedRole === role.id
                            ? "border-primary bg-primary/10"
                            : "border-border hover:border-primary/50"
                        }`}
                      >
                        <role.icon className="w-5 h-5 mt-0.5 text-primary" />
                        <div>
                          <div className="font-medium">{role.label}</div>
                          <div className="text-sm text-muted-foreground">
                            {role.description}
                          </div>
                        </div>
                      </button>
                    ))}
                  </div>
                </div>
              </>
            )}

            <Button type="submit" className="w-full" disabled={loading || authLoading}>
              {loading || authLoading ? "Please wait..." : isLogin ? "Sign In" : "Create Account"}
            </Button>

            {isLogin && (
              <div className="text-center text-sm">
                <button
                  type="button"
                  onClick={() => setShowForgotPassword(true)}
                  className="text-primary font-medium hover:underline"
                >
                  Forgot password?
                </button>
              </div>
            )}
          </form>
          )}

          {!showForgotPassword && (
            <div className="mt-4 text-center text-sm">
              {isLogin ? "Don't have an account?" : "Already have an account?"}{" "}
              <button
                onClick={() => {
                  setIsLogin(!isLogin);
                  setPassword("");
                  setUsername("");
                  setOrganizationName("");
                  setSelectedRole(null);
                }}
                className="text-primary font-medium hover:underline"
              >
                {isLogin ? "Sign up" : "Sign in"}
              </button>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
};

export default Auth;
