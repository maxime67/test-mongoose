/**
 * Fonctions utilitaires pour le traitement des CVE
 */

/**
 * Formatte les erreurs de validation Ajv de manière plus lisible
 * @param {Array} errors - Les erreurs retournées par Ajv
 * @returns {Array} - Erreurs formatées
 */
export function formatValidationErrors(errors) {
    if (!errors || !errors.length) return [];

    return errors.map(error => {
        return {
            path: error.instancePath,
            message: error.message,
            params: error.params,
            schemaPath: error.schemaPath
        };
    });
}

/**
 * Extrait la version CVSS à partir d'un vecteur
 * @param {string} vectorString - Chaîne de vecteur CVSS
 * @returns {string} - Version CVSS
 */
export function extractCvssVersion(vectorString) {
    if (!vectorString) return null;

    // CVSS:3.1/AV:...
    if (vectorString.startsWith('CVSS:')) {
        const versionMatch = vectorString.match(/CVSS:(\d+\.\d+)/);
        if (versionMatch && versionMatch[1]) {
            return versionMatch[1];
        }
    }

    // AV:N/AC:L/... (CVSS v2)
    if (vectorString.match(/^(AV:[NAL]|AC:[LMH]|Au:[MSN])/)) {
        return '2.0';
    }

    return null;
}

/**
 * Vérifie si un objet est un objet CVE valide en vérifiant sa structure de base
 * @param {Object} obj - L'objet à vérifier
 * @returns {boolean} - True si c'est un objet CVE valide de base
 */
export function isBasicCveObject(obj) {
    if (!obj || typeof obj !== 'object') return false;

    // Vérification minimale de la structure
    return (
        obj.dataType === 'CVE_RECORD' &&
        obj.dataVersion &&
        obj.cveMetadata &&
        obj.cveMetadata.cveId &&
        obj.containers
    );
}

/**
 * Calcule la sévérité globale à partir des scores CVSS disponibles
 * Privilégie les versions les plus récentes
 * @param {Array} cvssScores - Liste des scores CVSS
 * @returns {Object} - Informations sur la sévérité, avec score et version
 */
export function calculateOverallSeverity(cvssScores) {
    if (!cvssScores || !cvssScores.length) {
        return { severity: null, score: null, version: null };
    }

    // Priorité aux versions les plus récentes
    const versionPriority = {
        '4.0': 4,
        '3.1': 3,
        '3.0': 2,
        '2.0': 1
    };

    // Trier par priorité de version
    const sortedScores = [...cvssScores].sort((a, b) => {
        return (versionPriority[b.version] || 0) - (versionPriority[a.version] || 0);
    });

    // Utiliser le premier score comme référence (version la plus récente)
    const primaryScore = sortedScores[0];

    if (!primaryScore) {
        return { severity: null, score: null, version: null };
    }

    // Pour CVSS v3 et v4, utiliser directement la sévérité
    if (primaryScore.version === '3.0' || primaryScore.version === '3.1' || primaryScore.version === '4.0') {
        return {
            severity: primaryScore.baseSeverity || determineSeverityFromScore(primaryScore.baseScore, primaryScore.version),
            score: primaryScore.baseScore,
            version: primaryScore.version
        };
    }

    // Pour CVSS v2, calculer la sévérité
    return {
        severity: determineSeverityFromScore(primaryScore.baseScore, primaryScore.version),
        score: primaryScore.baseScore,
        version: primaryScore.version
    };
}

/**
 * Détermine le niveau de sévérité basé sur un score CVSS
 * @param {number} score - Score CVSS
 * @param {string} version - Version CVSS
 * @returns {string} - Niveau de sévérité
 */
export function determineSeverityFromScore(score, version) {
    if (score === null || score === undefined) return null;

    // CVSS v3.0, v3.1, v4.0
    if (version === '3.0' || version === '3.1' || version === '4.0') {
        if (score === 0) return 'NONE';
        if (score <= 3.9) return 'LOW';
        if (score <= 6.9) return 'MEDIUM';
        if (score <= 8.9) return 'HIGH';
        return 'CRITICAL';
    }

    // CVSS v2.0
    if (version === '2.0') {
        if (score === 0) return 'NONE';
        if (score <= 3.9) return 'LOW';
        if (score <= 6.9) return 'MEDIUM';
        return 'HIGH'; // v2 n'a pas de niveau CRITICAL
    }

    return null;
}

export default {
    formatValidationErrors,
    extractCvssVersion,
    isBasicCveObject,
    calculateOverallSeverity,
    determineSeverityFromScore
};