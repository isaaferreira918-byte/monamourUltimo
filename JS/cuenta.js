const accountPanel = document.getElementById("cuenta-panel");
const accountToggle = document.querySelector("[data-account-toggle]");

if (accountPanel && accountToggle) {
    const accountMessage = accountPanel.querySelector("[data-account-message]");
    const accountViews = {
        forms: accountPanel.querySelector('[data-account-view="forms"]'),
        signedIn: accountPanel.querySelector('[data-account-view="signed-in"]')
    };
    const accountForms = Array.from(accountPanel.querySelectorAll("[data-account-form]"));
    let csrfToken = "";
    let accountUser = null;
    let accountRequestPending = false;

    function showAccountMessage(message, isError = false) {
        accountMessage.textContent = message;
        accountMessage.classList.toggle("error", isError);
    }

    function setAccountUser(user) {
        accountUser = user;
        const signedIn = Boolean(user);
        accountViews.forms.hidden = signedIn;
        accountViews.signedIn.hidden = !signedIn;

        if (signedIn) {
            accountPanel.querySelector("[data-account-name]").textContent = user.name;
            accountPanel.querySelector("[data-account-email]").textContent = user.email;
            accountPanel.querySelector("[data-account-title]").textContent = "Mi cuenta";
            accountToggle.setAttribute("aria-label", `Cuenta de ${user.name}`);
        } else {
            accountPanel.querySelector("[data-account-title]").textContent = "Mi cuenta";
            accountToggle.setAttribute("aria-label", "Abrir cuenta");
        }
    }

    function selectAccountMode(mode) {
        accountForms.forEach((form) => {
            form.hidden = form.dataset.accountForm !== mode;
        });
        accountPanel.querySelectorAll("[data-account-mode]").forEach((tab) => {
            const selected = tab.dataset.accountMode === mode;
            tab.classList.toggle("is-active", selected);
            tab.setAttribute("aria-selected", String(selected));
            tab.tabIndex = selected ? 0 : -1;
        });
        showAccountMessage("");
    }

    async function requestAccount(action, fields = {}) {
        const headers = { "Accept": "application/json" };
        const options = { method: "GET", credentials: "same-origin", cache: "no-store", headers };

        if (action) {
            headers["Content-Type"] = "application/json";
            headers["X-CSRF-Token"] = csrfToken;
            options.method = "POST";
            options.body = JSON.stringify({ ...fields, action });
        }

        const response = await fetch("cuenta.php", options);
        let data;
        try {
            data = await response.json();
        } catch (error) {
            throw new Error("No se pudo conectar con la cuenta. Abrí el sitio desde un servidor con PHP para iniciar sesión o registrarte.");
        }

        if (!response.ok || !data.ok) {
            throw new Error(data.message || "No se pudo completar la operación.");
        }
        return data;
    }

    async function refreshAccount() {
        showAccountMessage("Cargando tu cuenta...");
        try {
            const data = await requestAccount();
            csrfToken = data.csrfToken;
            setAccountUser(data.user);
            showAccountMessage("");
        } catch (error) {
            const message = window.location.protocol === "file:"
                ? "Podés escribir tus datos, pero para registrarte o iniciar sesión tenés que abrir el sitio desde un servidor con PHP."
                : error.message;
            showAccountMessage(message, true);
        }
    }

    async function openAccountPanel() {
        const isOpen = !accountPanel.hidden;
        accountPanel.hidden = isOpen;
        accountToggle.setAttribute("aria-expanded", String(!isOpen));
        if (isOpen) {
            return;
        }

        const navigation = document.querySelector(".topbar");
        if (navigation) {
            accountPanel.style.top = `${Math.ceil(navigation.getBoundingClientRect().bottom + 8)}px`;
        }

        if (!accountUser || !csrfToken) {
            await refreshAccount();
        }
        accountPanel.querySelector(accountUser ? "[data-account-logout]" : "#cuenta-login-email")?.focus();
    }

    accountToggle.addEventListener("click", openAccountPanel);
    accountPanel.querySelector("[data-account-close]").addEventListener("click", () => {
        accountPanel.hidden = true;
        accountToggle.setAttribute("aria-expanded", "false");
        accountToggle.focus();
    });

    accountPanel.querySelectorAll("[data-account-mode]").forEach((tab) => {
        tab.addEventListener("click", () => selectAccountMode(tab.dataset.accountMode));
    });

    accountForms.forEach((form) => {
        form.addEventListener("submit", async (event) => {
            event.preventDefault();
            if (accountRequestPending) {
                return;
            }

            accountRequestPending = true;
            const submit = form.querySelector('[type="submit"]');
            submit.disabled = true;
            showAccountMessage("Procesando...");

            try {
                const fields = Object.fromEntries(new FormData(form).entries());
                const data = await requestAccount(form.dataset.accountForm, fields);
                csrfToken = data.csrfToken;
                setAccountUser(data.user);
                form.reset();
                showAccountMessage(data.message);
            } catch (error) {
                showAccountMessage(error.message, true);
            } finally {
                accountRequestPending = false;
                submit.disabled = false;
            }
        });
    });

    accountPanel.querySelector("[data-account-logout]").addEventListener("click", async () => {
        if (accountRequestPending) {
            return;
        }

        accountRequestPending = true;
        showAccountMessage("Cerrando sesión...");
        try {
            const data = await requestAccount("logout");
            csrfToken = data.csrfToken;
            setAccountUser(null);
            selectAccountMode("login");
            showAccountMessage(data.message);
        } catch (error) {
            showAccountMessage(error.message, true);
        } finally {
            accountRequestPending = false;
        }
    });

    document.addEventListener("keydown", (event) => {
        if (event.key === "Escape" && !accountPanel.hidden) {
            accountPanel.hidden = true;
            accountToggle.setAttribute("aria-expanded", "false");
            accountToggle.focus();
        }
    });

    document.addEventListener("click", (event) => {
        if (!accountPanel.hidden && !accountPanel.contains(event.target) && !accountToggle.contains(event.target)) {
            accountPanel.hidden = true;
            accountToggle.setAttribute("aria-expanded", "false");
        }
    });
}
