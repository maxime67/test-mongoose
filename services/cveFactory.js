import mongoose from 'mongoose';
import Cve from '../models/Cve.js'; // Assurez-vous que le chemin d'importation est correct

/**
 * Factory pour créer des instances du modèle Cve avec un mapping structuré
 */
export class CveFactory {
    /**
     * Crée une nouvelle instance du modèle Cve avec les valeurs par défaut
     * @returns {mongoose.Document} Instance du modèle Cve
     */
    static createEmpty() {
        return new Cve();
    }

    /**
     * Crée une instance du modèle Cve à partir d'un objet de données
     * @param {Object} data - Données pour initialiser l'instance Cve
     * @returns {mongoose.Document} Instance du modèle Cve
     */
    static create(data = {}) {
        // Créer une instance de base
        const cve = new Cve();

        // Appliquer les données si fournies
        if (data) {
            this.mapData(cve, data);
        }

        return cve;
    }

    /**
     * Mappe les données d'un objet vers une instance Cve existante
     * @param {mongoose.Document} cve - Instance du modèle Cve à mettre à jour
     * @param {Object} data - Données à mapper
     * @returns {mongoose.Document} Instance Cve mise à jour
     */
    static mapData(cve, data) {

        // Mapping des propriétés de premier niveau
        if (data.dataType) cve.dataType = data.dataType;
        if (data.dataVersion) cve.dataVersion = data.dataVersion;

        // Mapping des métadonnées CVE
        if (data.cveMetadata) {
            cve.cveMetadata = cve.cveMetadata || {};

            if (data.cveMetadata.cveId) cve.cveMetadata.cveId = data.cveMetadata.cveId;
            if (data.cveMetadata.assignerOrgId) cve.cveMetadata.assignerOrgId = data.cveMetadata.assignerOrgId;
            if (data.cveMetadata.assignerShortName) cve.cveMetadata.assignerShortName = data.cveMetadata.assignerShortName;
            if (data.cveMetadata.requesterUserId) cve.cveMetadata.requesterUserId = data.cveMetadata.requesterUserId;
            if (data.cveMetadata.dateReserved) cve.cveMetadata.dateReserved = data.cveMetadata.dateReserved;
            if (data.cveMetadata.datePublished) cve.cveMetadata.datePublished = data.cveMetadata.datePublished;
            if (data.cveMetadata.dateUpdated) cve.cveMetadata.dateUpdated = data.cveMetadata.dateUpdated;
            if (data.cveMetadata.state) cve.cveMetadata.state = data.cveMetadata.state;
            if (data.cveMetadata.serial) cve.cveMetadata.serial = data.cveMetadata.serial;
        }

        // Initialisation des conteneurs si nécessaire
        cve.containers = cve.containers || {};

        // Mapping du conteneur CNA
        if (data.containers && data.containers.cna) {
            cve.containers.cna = cve.containers.cna || {};

            // Mapping des métadonnées du fournisseur
            if (data.containers.cna.providerMetadata) {
                cve.containers.cna.providerMetadata = cve.containers.cna.providerMetadata || {};

                if (data.containers.cna.providerMetadata.orgId)
                    cve.containers.cna.providerMetadata.orgId = data.containers.cna.providerMetadata.orgId;
                if (data.containers.cna.providerMetadata.shortName)
                    cve.containers.cna.providerMetadata.shortName = data.containers.cna.providerMetadata.shortName;
                if (data.containers.cna.providerMetadata.dateUpdated)
                    cve.containers.cna.providerMetadata.dateUpdated = data.containers.cna.providerMetadata.dateUpdated;
            }

            // Dates
            if (data.containers.cna.dateAssigned) cve.containers.cna.dateAssigned = data.containers.cna.dateAssigned;
            if (data.containers.cna.datePublic) cve.containers.cna.datePublic = data.containers.cna.datePublic;

            // Titre
            if (data.containers.cna.title) cve.containers.cna.title = data.containers.cna.title;

            // Descriptions
            if (data.containers.cna.descriptions && Array.isArray(data.containers.cna.descriptions)) {
                cve.containers.cna.descriptions = data.containers.cna.descriptions.map(desc => ({
                    lang: desc.lang,
                    value: desc.value,
                    supportingMedia: desc.supportingMedia || []
                }));
            }

            // Produits affectés
            if (data.containers.cna.affected && Array.isArray(data.containers.cna.affected)) {
                cve.containers.cna.affected = data.containers.cna.affected.map(product => this.mapProduct(product));
            }

            // Types de problèmes
            if (data.containers.cna.problemTypes && Array.isArray(data.containers.cna.problemTypes)) {
                cve.containers.cna.problemTypes = data.containers.cna.problemTypes.map(problemType => ({
                    descriptions: problemType.descriptions || []
                }));
            }

            // Références
            if (data.containers.cna.references && Array.isArray(data.containers.cna.references)) {
                cve.containers.cna.references = data.containers.cna.references.map(ref => ({
                    url: ref.url,
                    name: ref.name,
                    tags: ref.tags || []
                }));
            }

            // Impacts
            if (data.containers.cna.impacts && Array.isArray(data.containers.cna.impacts)) {
                cve.containers.cna.impacts = data.containers.cna.impacts.map(impact => ({
                    capecId: impact.capecId,
                    descriptions: impact.descriptions || []
                }));
            }

            // Métriques
            if (data.containers.cna.metrics && Array.isArray(data.containers.cna.metrics)) {
                cve.containers.cna.metrics = data.containers.cna.metrics.map(metric => this.mapMetric(metric));
            }

            // Autres champs
            if (data.containers.cna.configurations) cve.containers.cna.configurations = data.containers.cna.configurations;
            if (data.containers.cna.workarounds) cve.containers.cna.workarounds = data.containers.cna.workarounds;
            if (data.containers.cna.solutions) cve.containers.cna.solutions = data.containers.cna.solutions;
            if (data.containers.cna.exploits) cve.containers.cna.exploits = data.containers.cna.exploits;
            if (data.containers.cna.timeline) cve.containers.cna.timeline = data.containers.cna.timeline;
            if (data.containers.cna.credits) cve.containers.cna.credits = data.containers.cna.credits;
            if (data.containers.cna.source) cve.containers.cna.source = data.containers.cna.source;
            if (data.containers.cna.tags) cve.containers.cna.tags = data.containers.cna.tags;
        }

        // Mapping des conteneurs ADP si présents
        if (data.containers && data.containers.adp && Array.isArray(data.containers.adp)) {
            cve.containers.adp = data.containers.adp.map(adp => this.mapAdpContainer(adp));
        }

        return cve;
    }

    /**
     * Mappe les données d'un produit
     * @param {Object} product - Données du produit
     * @returns {Object} Objet produit mappé
     */
    static mapProduct(product) {
        const mappedProduct = {
            vendor: product.vendor || 'Non spécifié',
            product: product.product || 'Non spécifié'
        };

        if (product.collectionURL) mappedProduct.collectionURL = product.collectionURL;
        if (product.packageName) mappedProduct.packageName = product.packageName;
        if (product.cpes) mappedProduct.cpes = product.cpes;
        if (product.modules) mappedProduct.modules = product.modules;
        if (product.programFiles) mappedProduct.programFiles = product.programFiles;
        if (product.programRoutines) mappedProduct.programRoutines = product.programRoutines;
        if (product.platforms) mappedProduct.platforms = product.platforms;
        if (product.repo) mappedProduct.repo = product.repo;
        if (product.defaultStatus) mappedProduct.defaultStatus = product.defaultStatus;

        if (product.versions && Array.isArray(product.versions)) {
            mappedProduct.versions = product.versions.map(version => ({
                version: version.version || 'n/a',
                status: version.status || 'unknown',
                versionType: version.versionType || 'custom',
                lessThan: version.lessThan || '',
                lessThanOrEqual: version.lessThanOrEqual || '',
                changes: version.changes || []
            }));
        }

        return mappedProduct;
    }

    /**
     * Mappe les données d'une métrique
     * @param {Object} metric - Données de la métrique
     * @returns {Object} Objet métrique mappé
     */
    static mapMetric(metric) {
        const mappedMetric = {
            format: metric.format || 'CVSS',
            scenarios: metric.scenarios || [{ lang: 'en', value: 'GENERAL' }]
        };

        // Mapping des différentes versions CVSS
        if (metric.cvssV2_0) mappedMetric.cvssV2_0 = metric.cvssV2_0;
        if (metric.cvssV3_0) mappedMetric.cvssV3_0 = metric.cvssV3_0;
        if (metric.cvssV3_1) mappedMetric.cvssV3_1 = metric.cvssV3_1;
        if (metric.cvssV4_0) mappedMetric.cvssV4_0 = metric.cvssV4_0;

        if (metric.other) mappedMetric.other = metric.other;

        return mappedMetric;
    }

    /**
     * Mappe les données d'un conteneur ADP
     * @param {Object} adp - Données du conteneur ADP
     * @returns {Object} Objet conteneur ADP mappé
     */
    static mapAdpContainer(adp) {
        const mappedAdp = {};

        if (adp.providerMetadata) mappedAdp.providerMetadata = adp.providerMetadata;
        if (adp.datePublic) mappedAdp.datePublic = adp.datePublic;
        if (adp.title) mappedAdp.title = adp.title;
        if (adp.descriptions) mappedAdp.descriptions = adp.descriptions;
        if (adp.affected) mappedAdp.affected = adp.affected.map(product => this.mapProduct(product));
        if (adp.problemTypes) mappedAdp.problemTypes = adp.problemTypes;
        if (adp.references) mappedAdp.references = adp.references;
        if (adp.impacts) mappedAdp.impacts = adp.impacts;
        if (adp.metrics) mappedAdp.metrics = adp.metrics.map(metric => this.mapMetric(metric));
        if (adp.configurations) mappedAdp.configurations = adp.configurations;
        if (adp.workarounds) mappedAdp.workarounds = adp.workarounds;
        if (adp.solutions) mappedAdp.solutions = adp.solutions;
        if (adp.exploits) mappedAdp.exploits = adp.exploits;
        if (adp.timeline) mappedAdp.timeline = adp.timeline;
        if (adp.credits) mappedAdp.credits = adp.credits;
        if (adp.source) mappedAdp.source = adp.source;
        if (adp.tags) mappedAdp.tags = adp.tags;

        return mappedAdp;
    }

    /**
     * Crée une nouvelle instance de Cve avec des valeurs minimales requises
     * @param {string} cveId - ID CVE au format 'CVE-YYYY-NNNN'
     * @param {string} title - Titre de la vulnérabilité
     * @param {string} description - Description de la vulnérabilité
     * @param {string} vendor - Nom du fournisseur affecté
     * @param {string} product - Nom du produit affecté
     * @returns {mongoose.Document} Instance du modèle Cve
     */
    static createMinimal(cveId, title, description, vendor, product) {
        const currentDate = new Date().toISOString();

        return this.create({
            dataType: 'CVE_RECORD',
            dataVersion: '5.1',
            cveMetadata: {
                cveId: cveId,
                state: 'PUBLISHED',
                dateReserved: currentDate,
                datePublished: currentDate,
                dateUpdated: currentDate
            },
            containers: {
                cna: {
                    title: title,
                    descriptions: [
                        {
                            lang: 'en',
                            value: description
                        }
                    ],
                    affected: [
                        {
                            vendor: vendor,
                            product: product
                        }
                    ],
                    references: [
                        {
                            url: 'https://example.com',
                            name: 'Référence par défaut'
                        }
                    ]
                }
            }
        });
    }

    /**
     * Ajoute une métrique CVSS 3.1 à un CVE existant
     * @param {mongoose.Document} cve - Instance du modèle Cve
     * @param {string} vectorString - Chaîne de vecteur CVSS 3.1
     * @param {number} baseScore - Score de base CVSS
     * @param {string} baseSeverity - Sévérité de base ('NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
     * @returns {mongoose.Document} Instance Cve mise à jour
     */
    static addCvss31Metric(cve, vectorString, baseScore, baseSeverity) {
        // Initialiser les conteneurs si nécessaire
        if (!cve.containers) cve.containers = {};
        if (!cve.containers.cna) cve.containers.cna = {};
        if (!cve.containers.cna.metrics) cve.containers.cna.metrics = [];

        // Extraire les composants du vecteur CVSS
        const components = {};
        const vectorParts = vectorString.replace('CVSS:3.1/', '').split('/');

        vectorParts.forEach(part => {
            const [key, value] = part.split(':');
            components[key] = value;
        });

        // Créer la métrique CVSS 3.1
        const cvssV31 = {
            version: '3.1',
            vectorString: vectorString,
            baseScore: baseScore,
            baseSeverity: baseSeverity,
            attackVector: this.mapCvssValue('AV', components.AV),
            attackComplexity: this.mapCvssValue('AC', components.AC),
            privilegesRequired: this.mapCvssValue('PR', components.PR),
            userInteraction: this.mapCvssValue('UI', components.UI),
            scope: this.mapCvssValue('S', components.S),
            confidentialityImpact: this.mapCvssValue('C', components.C),
            integrityImpact: this.mapCvssValue('I', components.I),
            availabilityImpact: this.mapCvssValue('A', components.A)
        };

        // Vérifier si des métriques temporelles sont présentes dans le vecteur
        if (components.E) cvssV31.exploitCodeMaturity = this.mapCvssValue('E', components.E);
        if (components.RL) cvssV31.remediationLevel = this.mapCvssValue('RL', components.RL);
        if (components.RC) cvssV31.reportConfidence = this.mapCvssValue('RC', components.RC);

        // Ajouter la métrique au CVE
        cve.containers.cna.metrics.push({
            format: 'CVSS',
            scenarios: [{ lang: 'en', value: 'GENERAL' }],
            cvssV3_1: cvssV31
        });

        return cve;
    }

    /**
     * Mappe les valeurs de vecteur CVSS vers leurs représentations complètes
     * @param {string} component - Composant CVSS
     * @param {string} value - Valeur abrégée
     * @returns {string} Valeur complète
     */
    static mapCvssValue(component, value) {
        if (!value) return undefined;

        const map = {
            'AV': {
                'N': 'NETWORK',
                'A': 'ADJACENT_NETWORK',
                'L': 'LOCAL',
                'P': 'PHYSICAL'
            },
            'AC': {
                'L': 'LOW',
                'H': 'HIGH'
            },
            'PR': {
                'N': 'NONE',
                'L': 'LOW',
                'H': 'HIGH'
            },
            'UI': {
                'N': 'NONE',
                'R': 'REQUIRED'
            },
            'S': {
                'U': 'UNCHANGED',
                'C': 'CHANGED'
            },
            'C': {
                'N': 'NONE',
                'L': 'LOW',
                'H': 'HIGH'
            },
            'I': {
                'N': 'NONE',
                'L': 'LOW',
                'H': 'HIGH'
            },
            'A': {
                'N': 'NONE',
                'L': 'LOW',
                'H': 'HIGH'
            },
            'E': {
                'X': 'NOT_DEFINED',
                'U': 'UNPROVEN',
                'P': 'PROOF_OF_CONCEPT',
                'F': 'FUNCTIONAL',
                'H': 'HIGH'
            },
            'RL': {
                'X': 'NOT_DEFINED',
                'O': 'OFFICIAL_FIX',
                'T': 'TEMPORARY_FIX',
                'W': 'WORKAROUND',
                'U': 'UNAVAILABLE'
            },
            'RC': {
                'X': 'NOT_DEFINED',
                'U': 'UNKNOWN',
                'R': 'REASONABLE',
                'C': 'CONFIRMED'
            }
        };

        return map[component] && map[component][value] ? map[component][value] : undefined;
    }
}

export default CveFactory;