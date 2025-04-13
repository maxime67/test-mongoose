import fs from 'fs-extra';
import CveValidator from './CveValidator.js';

class CveParser {
    constructor() {
        this.validator = new CveValidator();
    }

    /**
     * Charge un fichier JSON contenant une CVE
     * @param {string} filePath - Chemin vers le fichier JSON
     * @returns {Promise<Object>} - Objet CVE parsé
     */
    async loadCveFromFile(filePath) {
        try {
            console.log(`Chargement du fichier CVE: ${filePath}`);
            const cveData = await fs.readJson(filePath);
            return cveData;
        } catch (error) {
            console.error(`Erreur lors du chargement du fichier CVE: ${error.message}`);
            throw new Error(`Impossible de charger le fichier CVE: ${error.message}`);
        }
    }

    /**
     * Valide un objet CVE par rapport au schéma
     * @param {Object} cveObject - L'objet CVE à valider
     * @returns {Object} - Résultat de la validation
     */
    async validateCve(cveObject) {
        return this.validator.validate(cveObject);
    }

    /**
     * Construit un objet CVE enrichi avec des méthodes utiles
     * @param {Object} cveData - Données CVE brutes
     * @returns {Object} - Objet CVE enrichi
     */
    buildCveObject(cveData) {
        // Validation préliminaire
        const validationResult = this.validator.validate(cveData);
        if (!validationResult.valid) {
            console.warn('Le fichier CVE contient des erreurs de validation:',
                JSON.stringify(validationResult.errors, null, 2));
        }

        // Créer l'objet CVE enrichi
        const cveObject = {
            ...cveData,

            // Méthodes utilitaires ajoutées à l'objet
            getTitle() {
                if (cveData.containers && cveData.containers.cna && cveData.containers.cna.title) {
                    return cveData.containers.cna.title;
                }
                return null;
            },

            getCveId() {
                if (cveData.cveMetadata && cveData.cveMetadata.cveId) {
                    return cveData.cveMetadata.cveId;
                }
                return null;
            },

            getState() {
                if (cveData.cveMetadata && cveData.cveMetadata.state) {
                    return cveData.cveMetadata.state;
                }
                return null;
            },

            getDescription(lang = 'en') {
                if (cveData.containers && cveData.containers.cna && cveData.containers.cna.descriptions) {
                    const desc = cveData.containers.cna.descriptions.find(d => d.lang.startsWith(lang));
                    return desc ? desc.value : null;
                }
                return null;
            },

            getAffectedProducts() {
                if (cveData.containers && cveData.containers.cna && cveData.containers.cna.affected) {
                    return cveData.containers.cna.affected;
                }
                return [];
            },

            getProblemTypes() {
                if (cveData.containers && cveData.containers.cna && cveData.containers.cna.problemTypes) {
                    return cveData.containers.cna.problemTypes;
                }
                return [];
            },

            getReferences() {
                if (cveData.containers && cveData.containers.cna && cveData.containers.cna.references) {
                    return cveData.containers.cna.references;
                }
                return [];
            },

            getCvssScores() {
                const scores = [];
                if (cveData.containers && cveData.containers.cna && cveData.containers.cna.metrics) {
                    cveData.containers.cna.metrics.forEach(metric => {
                        if (metric.cvssV2_0) scores.push({ version: '2.0', ...metric.cvssV2_0 });
                        if (metric.cvssV3_0) scores.push({ version: '3.0', ...metric.cvssV3_0 });
                        if (metric.cvssV3_1) scores.push({ version: '3.1', ...metric.cvssV3_1 });
                        if (metric.cvssV4_0) scores.push({ version: '4.0', ...metric.cvssV4_0 });
                    });
                }
                return scores;
            },

            // Méthode pour obtenir la date de publication
            getPublishedDate() {
                if (cveData.cveMetadata && cveData.cveMetadata.datePublished) {
                    return new Date(cveData.cveMetadata.datePublished);
                }
                return null;
            },

            // Méthode pour obtenir les solutions/remediations
            getSolutions() {
                if (cveData.containers && cveData.containers.cna && cveData.containers.cna.solutions) {
                    return cveData.containers.cna.solutions;
                }
                return [];
            },

            // Méthode pour obtenir les workarounds
            getWorkarounds() {
                if (cveData.containers && cveData.containers.cna && cveData.containers.cna.workarounds) {
                    return cveData.containers.cna.workarounds;
                }
                return [];
            },

            // Renvoie l'objet CVE original
            getRawData() {
                return cveData;
            },

            // Convertit l'objet en chaîne JSON
            toJSON() {
                return JSON.stringify(cveData, null, 2);
            }
        };

        return cveObject;
    }

    /**
     * Méthode complète pour charger, valider et construire un objet CVE à partir d'un fichier
     * @param {string} filePath - Chemin vers le fichier JSON
     * @returns {Promise<Object>} - Objet CVE traité
     */
    async processCveFile(filePath) {
        try {
            // Charger les données du fichier
            const cveData = await this.loadCveFromFile(filePath);

            // Valider les données
            const validationResult = await this.validateCve(cveData);

            // Construire et retourner l'objet CVE, même si la validation échoue
            const cveObject = this.buildCveObject(cveData);

            return {
                cveObject,
                validationResult
            };
        } catch (error) {
            console.error(`Erreur lors du traitement du fichier CVE: ${error.message}`);
            throw error;
        }
    }
}

export default CveParser;