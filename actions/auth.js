"use server";

import { createAuthSession, destroySession } from "@/lib/auth";
import { hashUserPassword, verifyPassword } from "@/lib/hash";
import { createUser, getUserByEmail } from "@/lib/user";
import { redirect } from "next/navigation";

export async function signup(prevState, formData) {
  const email = formData.get("email");
  const password = formData.get("password");

  let errors = {};
  if (!email.includes("@")) {
    errors.email = "Please enter a valid email address.";
  }
  if (password.length < 8) {
    errors.password = "Your password must be at least 8 characters long.";
  }

  if (Object.keys(errors).length > 0) {
    return { errors };
  }

  const hashedPassword = hashUserPassword(password);
  try {
    const id = createUser(email, hashedPassword);
    await createAuthSession(id);
    redirect("/training");
  } catch (error) {
    if (error.message.includes("UNIQUE constraint failed")) {
      errors.email = "An account with this email address already exists.";
      return { errors };
    }
    throw error;
  }
}

export async function login(prevState, formData) {
  const email = formData.get("email");
  const password = formData.get("password");

  const user = getUserByEmail(email);
  if (!user) {
    return {
      errors: {
        email: "Couldn't authenticate user, please check your credentials.",
      },
    };
  }

  if (!verifyPassword(user.password, password)) {
    return {
      errors: {
        password: "Couldn't authenticate user, please check your credentials.",
      },
    };
  }

  await createAuthSession(user.id);
  redirect("/training");
}

export async function auth(mode, prevState, formData) {
  if (mode === "login") {
    return login(prevState, formData);
  }
  if (mode === "signup") {
    return signup(prevState, formData);
  }
  throw new Error("Invalid mode");
}

export async function logout() {
  await destroySession();
  redirect("/");
}
