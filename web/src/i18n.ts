import type { FileAnalysisStatus, FileTypeClass, Severity } from "./types";

export type Locale = "en" | "pl";

export interface RuleLocalizedMeta {
  id: string;
  cwe: string;
  owaspIot: string;
  etsi: string;
  vector: "auth" | "cloud" | "tls" | "net";
  subject: { en: string; pl: string };
  explanation: { en: string; pl: string };
  remediation: { en: string; pl: string };
}

export function formatFileType(ft: FileTypeClass | string, lang: Locale): string {
  const map: Record<string, { en: string; pl: string }> = {
    config: { en: "Config", pl: "Konfiguracja" },
    key_or_cert: { en: "Key / Cert", pl: "Klucz / Certyfikat" },
    script: { en: "Script", pl: "Skrypt" },
    data_or_binary: { en: "Binary / Data", pl: "Binarny / Dane" },
    documentation: { en: "Documentation", pl: "Dokumentacja" },
    other: { en: "Other", pl: "Inny" },
  };
  return map[ft]?.[lang] ?? ft;
}

export function formatAnalysisStatus(status: FileAnalysisStatus | string, lang: Locale): string {
  const map: Record<string, { en: string; pl: string }> = {
    scanned: { en: "Scanned", pl: "Przeskanowany" },
    skipped: { en: "Skipped", pl: "Pominięty" },
    truncated_or_limited: { en: "Truncated", pl: "Przycięty" },
    error: { en: "Error", pl: "Błąd" },
  };
  return map[status]?.[lang] ?? status;
}

export function formatSeverity(sev: Severity | string, lang: Locale): string {
  const map: Record<string, { en: string; pl: string }> = {
    high: { en: "HIGH", pl: "WYSOKIE" },
    medium: { en: "MEDIUM", pl: "ŚREDNIE" },
    low: { en: "LOW", pl: "NISKIE" },
    info: { en: "INFO", pl: "WSKAZÓWKA" },
  };
  return map[sev]?.[lang] ?? sev.toUpperCase();
}

export function formatSuppressionReason(reason: string, lang: Locale): string {
  const map: Record<string, { en: string; pl: string }> = {
    env_or_template_reference: {
      en: "Env / Template Reference",
      pl: "Zmienna środowiskowa / Szablon",
    },
    external_secret_reference: {
      en: "External Secret Store",
      pl: "Zewnętrzny magazyn sekretów",
    },
    placeholder_value: {
      en: "Placeholder Value",
      pl: "Wartość przykładowa",
    },
    empty_value: {
      en: "Empty Value",
      pl: "Pusta wartość",
    },
    public_certificate_or_key: {
      en: "Public Certificate / Key",
      pl: "Certyfikat lub klucz publiczny",
    },
    placeholder_pem_body: {
      en: "Sample PEM Block",
      pl: "Przykładowy blok PEM",
    },
    safe_configuration_value: {
      en: "Hardened Setting",
      pl: "Bezpieczne ustawienie",
    },
    uri_without_credentials: {
      en: "URI Without Credentials",
      pl: "Adres URI bez poświadczeń",
    },
  };
  return map[reason]?.[lang] ?? reason.replaceAll("_", " ");
}

export function formatVectorLabel(
  key: "auth" | "cloud" | "tls" | "net" | "safe",
  lang: Locale,
  options?: { compact?: boolean },
): string {
  const full: Record<"auth" | "cloud" | "tls" | "net" | "safe", { en: string; pl: string }> = {
    auth: { en: "Auth", pl: "Autoryzacja" },
    cloud: { en: "Cloud", pl: "Chmura" },
    tls: { en: "TLS/Key", pl: "Klucze TLS" },
    net: { en: "Net/URI", pl: "Sieć / URI" },
    safe: { en: "Safe", pl: "Bezpieczne" },
  };
  // Compact axis labels avoid PL word collision on the overview bar chart.
  const compact: Record<"auth" | "cloud" | "tls" | "net" | "safe", { en: string; pl: string }> = {
    auth: { en: "Auth", pl: "Auth" },
    cloud: { en: "Cloud", pl: "Chmura" },
    tls: { en: "TLS", pl: "TLS" },
    net: { en: "Net", pl: "Sieć" },
    safe: { en: "Safe", pl: "OK" },
  };
  return (options?.compact ? compact : full)[key][lang];
}

export const RULE_CATALOG: Record<string, RuleLocalizedMeta> = {
  FL001: {
    id: "FL001",
    cwe: "CWE-259 / CWE-798",
    owaspIot: "OWASP IoT I1: Hardcoded Passwords",
    etsi: "ETSI EN 303 645 5.1-1",
    vector: "auth",
    subject: {
      en: "Hardcoded password in configuration",
      pl: "Jawnie zaszyte hasło w konfiguracji",
    },
    explanation: {
      en: "A password assignment contains a literal value rather than a recognized external reference.",
      pl: "Przypisanie hasła zawiera stałą wartość tekstową zamiast referencji do bezpiecznego magazynu zewnętrznego.",
    },
    remediation: {
      en: "Provision unique credentials outside the firmware image and rotate exposed credentials.",
      pl: "Wstrzykuj unikalne poświadczenia poza obrazem firmware podczas parowania i zrotuj ujawnione hasła.",
    },
  },
  FL002: {
    id: "FL002",
    cwe: "CWE-798 / CWE-522",
    owaspIot: "OWASP IoT I1 & I3: Ecosystem Interfaces",
    etsi: "ETSI EN 303 645 5.1-1 / 5.5-5",
    vector: "cloud",
    subject: {
      en: "Hardcoded MQTT broker credentials",
      pl: "Poświadczenia brokera MQTT zaszyte w konfiguracji",
    },
    explanation: {
      en: "A literal password or token appears in MQTT configuration context.",
      pl: "Stałe hasło lub token dostępowy znajduje się bezpośrednio w sekcji konfiguracji brokera MQTT.",
    },
    remediation: {
      en: "Provision per-device broker credentials at deployment; restrict broker ACLs and rotate exposed credentials.",
      pl: "Generuj indywidualne poświadczenia MQTT dla każdego urządzenia przy wdrożeniu i ogranicz listy ACL brokera.",
    },
  },
  FL003: {
    id: "FL003",
    cwe: "CWE-321",
    owaspIot: "OWASP IoT I7: Data Transfer & Storage",
    etsi: "ETSI EN 303 645 5.4-1",
    vector: "tls",
    subject: {
      en: "Embedded PEM private key or TLS key marker",
      pl: "Zaszyty klucz prywatny PEM lub nagłówek klucza TLS",
    },
    explanation: {
      en: "Matching PEM private-key delimiters enclose a base64-shaped body. Cryptographic validity and encryption strength are not checked.",
      pl: "Znaczniki PEM klucza prywatnego otaczają blok Base64 zaszyty w obrazie lub wykryto nagłówek klucza w pliku binarnym.",
    },
    remediation: {
      en: "Generate device keys during provisioning and store them in protected hardware or a restricted external keystore.",
      pl: "Generuj klucze kryptograficzne podczas inicjalizacji urządzenia i przechowuj je w układzie TPM, HSM lub Secure Element.",
    },
  },
  FL004: {
    id: "FL004",
    cwe: "CWE-798",
    owaspIot: "OWASP IoT I3: Insecure Ecosystem Interfaces",
    etsi: "ETSI EN 303 645 5.5-5",
    vector: "auth",
    subject: {
      en: "Hardcoded API key or token",
      pl: "Zaszyty klucz lub token API",
    },
    explanation: {
      en: "An API key or token assignment contains a literal value.",
      pl: "Przypisanie klucza lub tokenu API zawiera stały ciąg uwierzytelniający zaszyty w obrazie.",
    },
    remediation: {
      en: "Inject scoped, short-lived API credentials at deployment and rotate exposed tokens.",
      pl: "Stosuj krótkotrwałe tokeny o ograniczonych uprawnieniach wstrzykiwane w środowisku uruchomieniowym.",
    },
  },
  FL005: {
    id: "FL005",
    cwe: "CWE-798",
    owaspIot: "OWASP IoT I1 / I9: Insecure Default Settings",
    etsi: "ETSI EN 303 645 5.4-3",
    vector: "auth",
    subject: {
      en: "Generic secret or master key assignment",
      pl: "Ogólny sekret lub klucz uwierzytelniający",
    },
    explanation: {
      en: "A secret or credential assignment contains a literal value; its use requires manual confirmation.",
      pl: "Parametr sekretu lub klucza głównego zawiera wartość literalną wymagającą weryfikacji kontekstowej.",
    },
    remediation: {
      en: "Move credentials out of the image and provision them through a protected deployment mechanism.",
      pl: "Usuń stałe sekrety z obrazu firmware i dostarczaj je przez bezpieczny mechanizm wdrożeniowy.",
    },
  },
  FL006: {
    id: "FL006",
    cwe: "CWE-798 / CWE-522",
    owaspIot: "OWASP IoT I7: Insecure Data Transfer & Storage",
    etsi: "ETSI EN 303 645 5.5-1",
    vector: "net",
    subject: {
      en: "Credentials embedded in connection URI",
      pl: "Poświadczenia zaszyte w adresie połączenia URI",
    },
    explanation: {
      en: "A URI contains a non-placeholder password in its user information section.",
      pl: "Adres połączenia URI zawiera jawne hasło bezpośrednio w sekcji użytkownika.",
    },
    remediation: {
      en: "Separate credentials from connection URLs, inject them securely, and rotate exposed values.",
      pl: "Oddziel poświadczenia od adresów URL połączeń i wstrzykuj je z bezpiecznego magazynu zmiennych.",
    },
  },
  FL007: {
    id: "FL007",
    cwe: "CWE-295",
    owaspIot: "OWASP IoT I7: Insecure Data Transfer",
    etsi: "ETSI EN 303 645 5.5-1 / 5.5-6",
    vector: "tls",
    subject: {
      en: "TLS certificate verification disabled",
      pl: "Wyłączona weryfikacja certyfikatów TLS",
    },
    explanation: {
      en: "A recognized configuration assignment explicitly disables TLS certificate verification.",
      pl: "Konfiguracja jawnie wyłącza weryfikację łańcucha certyfikatów TLS, umożliwiając ataki Man-in-the-Middle.",
    },
    remediation: {
      en: "Enable peer and hostname verification and provision a trusted CA bundle.",
      pl: "Wymuś pełną weryfikację certyfikatu serwera oraz nazwy hosta przy użyciu zaufanej puli CA.",
    },
  },
  FL008: {
    id: "FL008",
    cwe: "CWE-287 / CWE-306",
    owaspIot: "OWASP IoT I2: Insecure Network Services",
    etsi: "ETSI EN 303 645 5.5-5",
    vector: "net",
    subject: {
      en: "Anonymous service access enabled",
      pl: "Włączony dostęp anonimowy do usługi",
    },
    explanation: {
      en: "A recognized configuration assignment explicitly allows anonymous access.",
      pl: "Usługa sieciowa lub broker jawnie zezwala na połączenia bez uwierzytelniania.",
    },
    remediation: {
      en: "Require client authentication and apply least-privilege access controls.",
      pl: "Wyłącz dostęp anonimowy, wymuś uwierzytelnianie klientów i zastosuj zasadę najmniejszych uprawnień.",
    },
  },
  FL009: {
    id: "FL009",
    cwe: "CWE-798 / CWE-1392",
    owaspIot: "OWASP IoT I1 & I2: Network Services",
    etsi: "ETSI EN 303 645 5.1-1 / 5.6-1",
    vector: "net",
    subject: {
      en: "Static SNMP community string",
      pl: "Statyczny ciąg dostępowy SNMP Community",
    },
    explanation: {
      en: "An SNMP community assignment contains a literal access value, including well-known defaults.",
      pl: "Konfiguracja zawiera statyczny ciąg SNMP community dający dostęp do telemetrii lub zapisu.",
    },
    remediation: {
      en: "Disable unused SNMP or migrate to SNMPv3 authentication and encryption with unique credentials.",
      pl: "Wyłącz nieużywane SNMP lub przejdź na protokół SNMPv3 z indywidualnym uwierzytelnianiem i szyfrowaniem.",
    },
  },
  FL010: {
    id: "FL010",
    cwe: "CWE-798 / CWE-321",
    owaspIot: "OWASP IoT I3: Insecure Ecosystem Interfaces",
    etsi: "ETSI EN 303 645 5.4-1 / 5.4-3",
    vector: "cloud",
    subject: {
      en: "Device-to-cloud shared authentication key",
      pl: "Klucz uwierzytelniania Urządzenie-Chmura",
    },
    explanation: {
      en: "A static device-to-cloud shared access key, symmetric key, or connection secret is embedded in the image.",
      pl: "Statyczny klucz współdzielony SAS, klucz symetryczny lub sekret połączenia chmurowego jest zaszyty w obrazie.",
    },
    remediation: {
      en: "Use per-device hardware-backed identity and cloud fleet provisioning instead of static image credentials.",
      pl: "Użyj tożsamości sprzętowej TPM, HSM lub X.509 zamiast współdzielonych kluczy w obrazie firmware.",
    },
  },
  FL011: {
    id: "FL011",
    cwe: "CWE-798 / CWE-287",
    owaspIot: "OWASP IoT I1 & I8: Device Management",
    etsi: "ETSI EN 303 645 5.4-3",
    vector: "cloud",
    subject: {
      en: "Shared fleet provisioning or bootstrap token",
      pl: "Współdzielony token inicjalizacji i parowania floty",
    },
    explanation: {
      en: "A shared bootstrap or fleet enrollment secret is embedded in the firmware image.",
      pl: "Współdzielony sekret rejestracji floty lub token parowania jest zaszyty bezpośrednio w firmware.",
    },
    remediation: {
      en: "Replace shared enrollment secrets with per-device attestation or tightly scoped, short-lived bootstrap tokens.",
      pl: "Zastąp współdzielone tokeny wdrożeniowe atestacją urządzenia lub jednorazowymi tokenami parowania.",
    },
  },
  FL012: {
    id: "FL012",
    cwe: "CWE-798 / CWE-250",
    owaspIot: "OWASP IoT I3: Insecure Ecosystem Interfaces",
    etsi: "ETSI EN 303 645 5.4-3 / 5.5-5",
    vector: "cloud",
    subject: {
      en: "Embedded cloud service-account credentials",
      pl: "Zaszyte poświadczenia konta serwisowego chmury",
    },
    explanation: {
      en: "A cloud or backend service-account secret key or token is embedded inside device firmware.",
      pl: "Klucz konta serwisowego backendu lub chmury znajduje się bezpośrednio na urządzeniu brzegowym IoT.",
    },
    remediation: {
      en: "Never embed backend service-account credentials on edge devices; broker access through least-privilege device identities.",
      pl: "Nie umieszczaj kluczy kont serwisowych backendu w firmware; pośrednicz dostęp przez tożsamości o minimalnych uprawnieniach.",
    },
  },
};

export const UI_TEXT = {
  en: {
    menu: "Navigation",
    dashboard: "Dashboard",
    findings: "Findings",
    files: "Files & Config",
    diff: "Diff Profile",
    archiveUpload: "Firmware Upload",
    uploading: "Analyzing...",
    uploadBtn: "Upload Firmware",
    uploadMeta: "Max 256 MiB · Loopback 127.0.0.1",
    retainedScans: "Loaded Scans",
    emptyScansHint: "No scans loaded yet. Click '+ Upload Firmware' to analyze an archive or image.",
    actionableShort: "actionable",
    suppressedShort: "suppressed",
    partialShort: "Partial",
    fullShort: "Full",
    rulesCatalogBtn: "Security Standards & CWE",
    exportJson: "Export JSON",
    emptyDashboardSub:
      "Select a firmware archive (.tar, .tar.gz, .tgz, .zip) or binary image (.bin, .img, .fw, .chk, .pat) using the Upload Firmware button in the top bar.",
    headingOverview: "Dashboard",
    headingFindings: "Security Findings & Suppressions",
    headingFiles: "Files & Configuration Inspector",
    headingDiff: "Firmware Diff Comparison",
    schemaLabel: "Schema",
    scanTimeLabel: "Scan Time",
    partialBannerTitle: "Partial Coverage:",
    partialBannerBody:
      "One or more files were skipped, excluded, or limited. Partial coverage is never proof that skipped content is clean.",
    fullBannerTitle: "Full Scoped Coverage:",
    fullBannerBody: "All in-scope files were analyzed within configured resource budgets.",
    postureTitle: "Security Posture Status",
    candidatesLabel: "Candidates",
    filesScannedSub: "Files Scanned",
    suppressedLegend: "Suppressed",
    actionableLegend: "Actionable",
    reviewHintLegend: "Review / Hint",
    vectorsTitle: "Findings by IoT Vector",
    actionableVectorLegend: "Actionable Vector",
    hardenedSafeLegend: "Hardened / Safe",
    ruleProfileTitle: "Security Rule Coverage",
    rulesetBadge: "Ruleset v",
    suppressedRefLegend: "Suppressed Reference",
    triggeredRuleLegend: "Triggered Rule",
    selectedTreeTitle: "Selected Firmware Tree",
    totalNodes: "Total Nodes:",
    vulnerableNodes: "Vulnerable:",
    cleanNodes: "Clean/Hardened:",
    skippedNodes: "Skipped:",
    filesystemNodes: "Filesystem Nodes",
    topologyConstellation: "TOPOLOGY CONSTELLATION",
    clickNodeHint: "Click any node to inspect",
    cleanNodeLegend: "Hardened / Clean Node",
    skippedNodeLegend: "Skipped / Hint Node",
    secretNodeLegend: "Actionable Secret Node",
    kpiActionable: "Actionable",
    kpiReview: "Review Candidates",
    kpiHints: "Informational Hints",
    kpiSuppressed: "Suppressed",
    kpiFilesScanned: "Files Scanned",
    kpiSkipped: "Skipped Entries",
    provenanceTitle: "Ingestion Provenance",
    archiveRoot: "Archive Root",
    inputKindOutcome: "Input Kind / Outcome",
    expandedExtracted: "Expanded Bytes / Extracted Files",
    cleanupVerified: "Temporary Workspace Cleanup Verified",
    yes: "Yes",
    no: "No",
    pathCol: "Path",
    reasonCol: "Reason",
    filterAll: "All Candidates & Suppressions",
    filterActionable: "Actionable Only",
    filterReview: "Requires Review Only",
    filterHints: "Informational Hints Only",
    filterSuppressed: "Suppressed Only",
    searchPlaceholder: "Filter by problem name, CWE, vector, or file path...",
    clearFilter: "Clear Filter",
    redactedEvidence: "Vulnerable Config Fragment:",
    remediationLabel: "Remediation:",
    standardsLabel: "IoT Standards:",
    allStatuses: "All Statuses",
    statusScanned: "Scanned",
    statusSkipped: "Skipped",
    statusTruncated: "Truncated / Limited",
    statusError: "Error",
    typeCol: "Type",
    sizeCol: "Size in Bytes",
    statusCol: "Status",
    baseScanLabel: "Base Scan:",
    targetScanLabel: "Target Scan:",
    selectBase: "Select base...",
    selectTarget: "Select target...",
    coverageCaveat: "Coverage Caveat:",
    actionableDelta: "Actionable Δ",
    suppressedDelta: "Suppressed Δ",
    resolvedCandidates: "Resolved Candidates",
    newCandidates: "New Candidates",
    resolvedFindingsTitle: "Resolved Findings",
    newFindingsTitle: "Newly Introduced Findings",
    diffEmptyHint: "Select two uploaded scans to compare their security posture.",
    modalRulesTitle: "IoT Security Standards & Vulnerability Catalog",
    modalRulesSub:
      "All detection policies map directly to MITRE CWE, OWASP IoT Top 10, and ETSI EN 303 645 cybersecurity provisions.",
    closeBtn: "Close",
    inspectRuleBtn: "Filter Findings",
    deleteScanTitle: "Remove scan from memory",
    openInFileBtn: "Inspect in file",
    codeInspectorTitle: "Configuration & Code Inspector",
    codeInspectorEmpty: "Select any file from the table or click a file link on a finding to inspect its vulnerable configuration fragments.",
    cleanFileMessage: "This file was scanned and contains no exposed secrets or insecure configuration directives.",
    skippedFileMessage: "This file was skipped during analysis due to scope or resource policy.",
    lineLabel: "Line",
    offsetLabel: "Offset",
    viewAllFindingsInFile: "Filter all in Findings tab",
  },
  pl: {
    menu: "Nawigacja",
    dashboard: "Panel główny",
    findings: "Wykrycia",
    files: "Pliki i konfiguracja",
    diff: "Porównanie wersji",
    archiveUpload: "Wgrywanie firmware",
    uploading: "Analizowanie...",
    uploadBtn: "Wgraj Firmware",
    uploadMeta: "Maks. 256 MiB · Loopback 127.0.0.1",
    retainedScans: "Wgrane skany",
    emptyScansHint: "Brak wgranych skanów. Kliknij '+ Wgraj Firmware', aby przeanalizować plik.",
    actionableShort: "zagrożeń",
    suppressedShort: "wyciszonych",
    partialShort: "Częściowy",
    fullShort: "Pełny",
    rulesCatalogBtn: "Standardy CWE i OWASP",
    exportJson: "Eksportuj JSON",
    emptyDashboardSub:
      "Wybierz archiwum oprogramowania (.tar, .tar.gz, .tgz, .zip) lub obraz binarny (.bin, .img, .fw, .chk, .pat) za pomocą przycisku Wgraj Firmware na górnym pasku.",
    headingOverview: "Panel analityczny",
    headingFindings: "Wykryte problemy bezpieczeństwa",
    headingFiles: "Inspektor plików i konfiguracji",
    headingDiff: "Porównanie wersji firmware",
    schemaLabel: "Schemat",
    scanTimeLabel: "Czas skanu",
    partialBannerTitle: "Pokrycie częściowe:",
    partialBannerBody:
      "Co najmniej jeden plik został pominięty, wykluczony lub ograniczony budżetem. Pokrycie częściowe nie stanowi dowodu, że pominięte pliki są bezpieczne.",
    fullBannerTitle: "Pełne pokrycie zakresu:",
    fullBannerBody: "Wszystkie pliki w zakresie zostały przeanalizowane w ramach skonfigurowanych limitów zasobów.",
    postureTitle: "Status bezpieczeństwa obrazu",
    candidatesLabel: "Kandydatów",
    filesScannedSub: "Przeskanowanych plików",
    suppressedLegend: "Bezpieczne / Wyciszone",
    actionableLegend: "Zagrożenia",
    reviewHintLegend: "Do weryfikacji / Wskazówki",
    vectorsTitle: "Wykrycia wg wektora IoT",
    actionableVectorLegend: "Wektor zagrożenia",
    hardenedSafeLegend: "Utwardzone / Bezpieczne",
    ruleProfileTitle: "Pokrycie kategorii bezpieczeństwa",
    rulesetBadge: "Zestaw v",
    suppressedRefLegend: "Zewnętrzna referencja",
    triggeredRuleLegend: "Wykryty problem",
    selectedTreeTitle: "Drzewo systemu plików firmware",
    totalNodes: "Wszystkie węzły:",
    vulnerableNodes: "Podatne:",
    cleanNodes: "Czyste / Utwardzone:",
    skippedNodes: "Pominięte:",
    filesystemNodes: "Węzły systemu plików",
    topologyConstellation: "KONSTELACJA TOPOLOGII",
    clickNodeHint: "Kliknij dowolny węzeł, aby zbadać plik",
    cleanNodeLegend: "Węzeł utwardzony / czysty",
    skippedNodeLegend: "Węzeł pominięty / wskazówka",
    secretNodeLegend: "Węzeł z wykrytym sekretem",
    kpiActionable: "Zagrożenia",
    kpiReview: "Do weryfikacji",
    kpiHints: "Wskazówki",
    kpiSuppressed: "Wyciszone",
    kpiFilesScanned: "Przeskanowane pliki",
    kpiSkipped: "Pominięte wpisy",
    provenanceTitle: "Pochodzenie i bezpieczeństwo ingestii",
    archiveRoot: "Źródło archiwum",
    inputKindOutcome: "Typ wejścia / Wynik",
    expandedExtracted: "Rozpakowane bajty / Wyodrębnione pliki",
    cleanupVerified: "Weryfikacja usunięcia katalogu tymczasowego",
    yes: "Tak",
    no: "Nie",
    pathCol: "Ścieżka",
    reasonCol: "Powód",
    filterAll: "Wszystkie wykrycia i wyciszenia",
    filterActionable: "Tylko zagrożenia",
    filterReview: "Tylko do weryfikacji",
    filterHints: "Tylko wskazówki",
    filterSuppressed: "Tylko wyciszone",
    searchPlaceholder: "Filtruj po nazwie problemu, CWE, wektorze lub ścieżce pliku...",
    clearFilter: "Wyczyść filtr",
    redactedEvidence: "Narażony fragment konfiguracji:",
    remediationLabel: "Zalecenie naprawcze:",
    standardsLabel: "Standardy IoT:",
    allStatuses: "Wszystkie statusy",
    statusScanned: "Przeskanowane",
    statusSkipped: "Pominięte",
    statusTruncated: "Przycięte / Limit",
    statusError: "Błąd",
    typeCol: "Typ",
    sizeCol: "Rozmiar w bajtach",
    statusCol: "Status",
    baseScanLabel: "Skan bazowy:",
    targetScanLabel: "Skan docelowy:",
    selectBase: "Wybierz bazowy...",
    selectTarget: "Wybierz docelowy...",
    coverageCaveat: "Ostrzeżenie o pokryciu:",
    actionableDelta: "Zmiana zagrożeń Δ",
    suppressedDelta: "Zmiana wyciszeń Δ",
    resolvedCandidates: "Rozwiązane podatności",
    newCandidates: "Nowe podatności",
    resolvedFindingsTitle: "Rozwiązane wykrycia",
    newFindingsTitle: "Nowo wprowadzone wykrycia",
    diffEmptyHint: "Wybierz dwa wgrane skany, aby porównać ich stan bezpieczeństwa.",
    modalRulesTitle: "Katalog problemów bezpieczeństwa IoT i mapowanie standardów",
    modalRulesSub:
      "Wszystkie reguły detekcji odpowiadają standardom MITRE CWE, OWASP IoT Top 10 oraz normie ETSI EN 303 645.",
    closeBtn: "Zamknij",
    inspectRuleBtn: "Filtruj wykrycia",
    deleteScanTitle: "Usuń skan z pamięci",
    openInFileBtn: "Pokaż w pliku",
    codeInspectorTitle: "Inspektor kodu i konfiguracji",
    codeInspectorEmpty: "Wybierz plik z listy lub kliknij odnośnik przy wykryciu, aby zobaczyć narażony fragment konfiguracji.",
    cleanFileMessage: "Plik został przeskanowany. Brak zaszytych poświadczeń oraz niebezpiecznych dyrektyw konfiguracyjnych.",
    skippedFileMessage: "Plik został pominięty zgodnie z polityką zakresu lub limitów zasobów.",
    lineLabel: "Linia",
    offsetLabel: "Offset",
    viewAllFindingsInFile: "Pokaż w karcie Wykrycia",
  },
} as const;
