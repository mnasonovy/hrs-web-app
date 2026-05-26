document.addEventListener("DOMContentLoaded", () => {
    animateCards();
    markActiveNav();
    bindDangerConfirmations();
    createScrollTopButton();
});

function animateCards() {
    const elements = document.querySelectorAll(
        ".panel, .stat-card, .incident-card, .arch-node"
    );

    elements.forEach((element, index) => {
        element.style.opacity = "0";
        element.style.transform = "translateY(18px)";
        element.style.transition = "opacity 0.45s ease, transform 0.45s ease";

        setTimeout(() => {
            element.style.opacity = "1";
            element.style.transform = "translateY(0)";
        }, 70 * index);
    });
}

function markActiveNav() {
    const currentPath = window.location.pathname;
    const links = document.querySelectorAll(".nav-link");

    links.forEach((link) => {
        const href = link.getAttribute("href");

        if (href === currentPath) {
            link.classList.add("active");
            return;
        }

        if (href !== "/" && currentPath.startsWith(href)) {
            link.classList.add("active");
        }
    });
}

function bindDangerConfirmations() {
    const dangerButtons = document.querySelectorAll("[data-confirm]");

    dangerButtons.forEach((button) => {
        button.addEventListener("click", (event) => {
            const message = button.getAttribute("data-confirm");

            if (!confirm(message)) {
                event.preventDefault();
            }
        });
    });
}

function createScrollTopButton() {
    const button = document.createElement("button");

    button.textContent = "↑";
    button.setAttribute("aria-label", "Наверх");

    button.style.position = "fixed";
    button.style.right = "22px";
    button.style.bottom = "22px";
    button.style.width = "48px";
    button.style.height = "48px";
    button.style.borderRadius = "16px";
    button.style.border = "1px solid rgba(34, 211, 238, 0.35)";
    button.style.background = "linear-gradient(135deg, #3b82f6, #22d3ee)";
    button.style.color = "#ffffff";
    button.style.fontWeight = "900";
    button.style.fontSize = "22px";
    button.style.cursor = "pointer";
    button.style.opacity = "0";
    button.style.pointerEvents = "none";
    button.style.transition = "0.2s ease";
    button.style.zIndex = "50";

    document.body.appendChild(button);

    window.addEventListener("scroll", () => {
        if (window.scrollY > 400) {
            button.style.opacity = "1";
            button.style.pointerEvents = "auto";
        } else {
            button.style.opacity = "0";
            button.style.pointerEvents = "none";
        }
    });

    button.addEventListener("click", () => {
        window.scrollTo({
            top: 0,
            behavior: "smooth",
        });
    });
}
