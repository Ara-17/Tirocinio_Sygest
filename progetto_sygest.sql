SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";

CREATE TABLE `targets` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `hostname` varchar(255) NOT NULL,
  `active` tinyint(1) NOT NULL DEFAULT 1,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `hostname` (`hostname`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `scans` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `target_id` int(11) NOT NULL,
  `thumbprint` varchar(64) NOT NULL,
  `expire_date` datetime NOT NULL,
  `missing_headers` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL CHECK (json_valid(`missing_headers`)),
  `full_report` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL CHECK (json_valid(`full_report`)),
  `scanned_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `idx_target_scanned` (`target_id`,`scanned_at`),
  CONSTRAINT `fk_scans_targets` FOREIGN KEY (`target_id`) REFERENCES `targets` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `vulnerabilities` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `target_id` int(11) NOT NULL,
  `cve_id` varchar(100) NOT NULL,
  `software` varchar(255) NOT NULL,
  `current_version` varchar(255) DEFAULT NULL,
  `fixed_version` varchar(255) DEFAULT NULL,
  `severity` varchar(50) DEFAULT NULL,
  `description` text,
  `link_patch` text,
  `first_seen` timestamp NOT NULL DEFAULT current_timestamp(),
  `last_seen` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_target_cve_software` (`target_id`,`cve_id`,`software`),
  CONSTRAINT `fk_vuln_target` FOREIGN KEY (`target_id`) REFERENCES `targets` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Inserisco i target di base
INSERT INTO `targets` (`id`, `hostname`, `active`) VALUES
(3, 'Jbt-packinglist-macchine.sys-suite.com', 0),
(4, 'Logistica.fortna.it', 0),
(5, 'PackinglistCFT.sygest.it', 1),
(6, 'Packinglist-cft.sys-suite.com', 0),
(7, 'Packinglistmmtest-fortna.sygest.it', 0),
(8, 'plextendedtest.sygest.it', 0),
(9, 'spcbweb.sys-suite.com', 1);

COMMIT;