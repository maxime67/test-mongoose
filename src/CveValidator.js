import Ajv from 'ajv';
import fs from 'fs-extra';
import path from 'path';
import { fileURLToPath } from 'url';

// Obtenir le chemin du répertoire actuel
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

class CveValidator {
    constructor() {
        this.ajv = new Ajv({ allErrors: true, verbose: true });
        this.schemas = {};
        this.loadSchemas();
    }

    /**
     * Charge tous les schémas JSON nécessaires pour la validation
     */
    async loadSchemas() {
        try {
            // Chemin vers le répertoire des schémas
            const schemasDir = path.resolve(__dirname, '../schemas');

            // Charger le schéma principal CVE
            const cveSchema = await fs.readJson(path.join(schemasDir, 'CVE_Record_Format.json'));
            this.schemas.cve = cveSchema;

            // Charger les schémas CVSS
            const cvssDir = path.join(schemasDir, 'imports/cvss');
            this.schemas.cvss = {
                v2: await fs.readJson(path.join(cvssDir, 'cvss-v2.0.json')),
                v3_0: await fs.readJson(path.join(cvssDir, 'cvss-v3.0.json')),
                v3_1: await fs.readJson(path.join(cvssDir, 'cvss-v3.1.json')),
                v4_0: await fs.readJson(path.join(cvssDir, 'cvss-v4.0.json'))
            };

            // Charger les schémas de tags
            const tagsDir = path.join(schemasDir, 'tags');
            this.schemas.tags = {
                adp: await fs.readJson(path.join(tagsDir, 'adp-tags.json')),
                cna: await fs.readJson(path.join(tagsDir, 'cna-tags.json')),
                reference: await fs.readJson(path.join(tagsDir, 'reference-tags.json'))
            };

            // Ajouter tous les schémas à AJV
            this.addSchemasToAjv();

            console.log('Tous les schémas ont été chargés avec succès.');
        } catch (error) {
            console.error('Erreur lors du chargement des schémas:', error);
            throw error;
        }
    }

    /**
     * Ajoute tous les schémas à l'instance Ajv
     */
    addSchemasToAjv() {
        // Gérer les références aux schémas dans AJV

        // Ajouter les schémas CVSS
        for (const [version, schema] of Object.entries(this.schemas.cvss)) {
            this.ajv.addSchema(schema, `file:imports/cvss/cvss-${version}.json`);
        }

        // Ajouter les schémas de tags
        for (const [type, schema] of Object.entries(this.schemas.tags)) {
            this.ajv.addSchema(schema, `file:tags/${type}-tags.json`);
        }

        // Ajouter le schéma CVE principal en dernier pour s'assurer que toutes les références sont disponibles
        this.ajv.addSchema(this.schemas.cve);
    }

    /**
     * Valide un objet CVE par rapport au schéma
     * @param {Object} cveObject - L'objet CVE à valider
     * @returns {Object} Résultat de la validation { valid, errors }
     */
    validate(cveObject) {
        const validate = this.ajv.compile(this.schemas.cve);
        const valid = validate(cveObject);

        return {
            valid,
            errors: validate.errors || []
        };
    }

    /**
     * Vérifie la version de la CVE et sélectionne le bon schéma pour la validation
     * @param {Object} cveObject - L'objet CVE à valider
     * @returns {String} La version détectée
     */
    detectCveVersion(cveObject) {
        if (!cveObject || !cveObject.dataVersion) {
            throw new Error('Impossible de détecter la version CVE: dataVersion manquante');
        }
        return cveObject.dataVersion;
    }
}

export default CveValidator;