const searchInput = document.querySelector('input[name="search"]');
const categorySelect = document.querySelector('select[name="category"]');
const tableBody = document.querySelector("tbody");

const rows = Array.from(tableBody.querySelectorAll("tr")).filter(row => {
    return row.querySelectorAll("td").length > 1;
});

function filterTable() {
    const searchValue = searchInput.value.toLowerCase().trim();
    const selectedCategory = categorySelect.value.toLowerCase();

    let visibleCount = 0;

    rows.forEach(row => {
        const rowText = row.textContent.toLowerCase();

        const matchesSearch = rowText.includes(searchValue);

        const categoryCell = row.querySelectorAll("td")[1];
        const rowCategory = categoryCell
            ? categoryCell.textContent.trim().toLowerCase()
            : "";

        const matchesCategory =
            selectedCategory === "all" ||
            rowCategory === selectedCategory;

        const shouldShow = matchesSearch && matchesCategory;

        row.style.display = shouldShow ? "" : "none";

        if (shouldShow) {
            visibleCount++;
        }
    });

    let noResults = document.getElementById("no-results");

    if (!noResults) {
        noResults = document.createElement("tr");
        noResults.id = "no-results";
        noResults.innerHTML =
            '<td colspan="5">No results found</td>';
        tableBody.appendChild(noResults);
    }

    noResults.style.display = visibleCount === 0 ? "" : "none";
}

searchInput.addEventListener("input", filterTable);
categorySelect.addEventListener("change", filterTable);
