(() => {
	const modal = document.getElementById("token-modal");
	const btn = document.getElementById("modal-close-btn");
	const handleClick = () => {
		modal.classList.add("hidden");
	};

	btn.addEventListener("click", handleClick);
	modal.addEventListener("click", handleClick);

	document.getElementById("modal-content").addEventListener("click", (e) => {
		e.stopPropagation();
	});
})();
