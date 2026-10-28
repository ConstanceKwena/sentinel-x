"use strict";

const form = document.querySelector("#login-form");
const result = document.querySelector("#result");

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = form.querySelector("button");
  button.disabled = true;
  result.className = "";
  result.textContent = "Contacting the demo application…";
  try {
    const response = await fetch("/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: form.elements.username.value,
        password: form.elements.password.value,
      }),
    });
    const body = await response.json();
    if (!response.ok) throw new Error(body.detail || "Login request failed.");
    result.textContent = body.message;
    result.classList.toggle("error", !body.authenticated);
  } catch (error) {
    result.textContent = error.message;
    result.classList.add("error");
  } finally {
    button.disabled = false;
  }
});
