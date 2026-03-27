SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";

CREATE TABLE `targets` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `hostname` varchar(255) NOT NULL,
  `target_type` varchar(10) NOT NULL DEFAULT 'WEB',
  `active` tinyint(1) NOT NULL DEFAULT 1,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_hostname_type` (`hostname`, `target_type`)
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
INSERT INTO `targets` (`hostname`, `target_type`, `active`) VALUES
('jbt-packinglist-macchine.sys-suite.com', 'WEB', 1),
('logistica.fortna.it', 'WEB', 1),
('packinglistCFT.sygest.it', 'WEB', 1),
('packinglist-cft.sys-suite.com', 'WEB', 1),
('packinglistmmtest-fortna.sygest.it', 'WEB', 1),
('packinglistPEI-test.sygest.it', 'WEB', 1),
('placmi-test.sygest.it', 'WEB', 1),
('plextendedtest.sygest.it', 'WEB', 1),
('plmarchesini-test.sygest.it', 'WEB', 1),
('packinglist.ocme.com', 'WEB', 1),
('packinglistchimar.sygest.it', 'WEB', 1),
('spcbweb.sys-suite.com', 'WEB', 1),
('packinglistequipment.ocme.com', 'WEB', 1),
('packinglistgebo.sygest.it', 'WEB', 1),
('packinglistrobopac.sygest.it', 'WEB', 1),
('packinglistrobopactest.sygest.it', 'WEB', 1),
('pldemomm.sygest.it', 'WEB', 1),
('packinglistzacmi.sygest.it', 'WEB', 1),
('packinglistsidel.sidel.com', 'WEB', 1),
('plocme.sygest.it', 'WEB', 1),
('plextendedsvil.sygest.it', 'WEB', 1),
('pit-plp.sys-suite.com', 'WEB', 1),
('jbtams-packinglist.sys-suite.com', 'WEB', 1),
('termotecnicapericoli-plp.sys-suite.com', 'WEB', 1),
('clevertech-plp.sys-suite.com', 'WEB', 1),
('jbt-packinglist.sys-suite.com', 'WEB', 1),
('acmi-plp.sys-suite.com', 'WEB', 1),
('packinglist.sidel.com', 'WEB', 1),
('eparts-filling.gea.com', 'WEB', 1),
('sparepartsadmin-procomac.gea.com', 'WEB', 1),
('hom.spareparts.gea.com', 'WEB', 1),
('admin.hom.spareparts.gea.com', 'WEB', 1),
('extrudedfood.spareparts.gea.com', 'WEB', 1),
('admin.extrudedfood.spareparts.gea.com', 'WEB', 1);

COMMIT;