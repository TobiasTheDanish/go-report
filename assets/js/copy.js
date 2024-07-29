me("-").addEventListener("click", function() {
	navigator.clipboard.writeText(this.getAttribute("data-copy-clipboard"));
});
