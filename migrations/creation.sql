CREATE TABLE IF NOT EXISTS `report_owners` (
	`id` INTEGER PRIMARY KEY AUTOINCREMENT,
	`name` TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS `report_installations` (
	`id` INTEGER PRIMARY KEY AUTOINCREMENT,
	`owner_id` INTEGER,
	FOREIGN KEY (`owner_id`) REFERENCES `report_owners` (`id`)
);
