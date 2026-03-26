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
  `score` int(11) NOT NULL DEFAULT 0,
  `headers_grade` varchar(5) NOT NULL DEFAULT 'N/A',
  `ssl_grade` varchar(5) NOT NULL DEFAULT 'N/A',
  `days_left` int(11) DEFAULT NULL,
  `thumbprint` varchar(100) DEFAULT 'N/A',
  `warnings_text` text,
  `full_report` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
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

-- Inserisco la lista completa dei target
INSERT INTO `targets` (`hostname`, `active`) VALUES
('jbt-packinglist-macchine.sys-suite.com', 1),
('logistica.fortna.it', 1),
('packinglistCFT.sygest.it', 1),
('packinglist-cft.sys-suite.com', 1),
('packinglistmmtest-fortna.sygest.it', 1),
('packinglistPEI-test.sygest.it', 1),
('placmi-test.sygest.it', 1),
('plextendedtest.sygest.it', 1),
('plmarchesini-test.sygest.it', 1),
('packinglist.ocme.com', 1),
('packinglistchimar.sygest.it', 1),
('spcbweb.sys-suite.com', 1),
('packinglistequipment.ocme.com', 1),
('packinglistgebo.sygest.it', 1),
('packinglistrobopac.sygest.it', 1),
('packinglistrobopactest.sygest.it', 1),
('pldemomm.sygest.it', 1),
('packinglistzacmi.sygest.it', 1),
('packinglistsidel.sidel.com', 1),
('plocme.sygest.it', 1),
('plextendedsvil.sygest.it', 1),
('pit-plp.sys-suite.com', 1),
('jbtams-packinglist.sys-suite.com', 1),
('termotecnicapericoli-plp.sys-suite.com', 1),
('clevertech-plp.sys-suite.com', 1),
('jbt-packinglist.sys-suite.com', 1),
('acmi-plp.sys-suite.com', 1),
('packinglist.sidel.com', 1),
('eparts-filling.gea.com', 1),
('sparepartsadmin-procomac.gea.com', 1),
('hom.spareparts.gea.com', 1),
('admin.hom.spareparts.gea.com', 1),
('extrudedfood.spareparts.gea.com', 1),
('admin.extrudedfood.spareparts.gea.com', 1);

COMMIT;