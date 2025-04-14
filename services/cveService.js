import Cve from '../models/Cve.js';
import cveFactory from "../services/cveFactory.js"
/**
 * Service pour gérer les opérations liées aux CVE
 */
const cveService = {
    /**
     * Insère un nouveau CVE dans la base de données
     * @param {Object} cveData - Données du CVE à insérer
     * @returns {Promise<Object>} - Le CVE inséré
     */
    async insertCve(cveData) {
        try {
            if(cveData.cveMetadata.cveId === "CVE-2025-20169"){
                console.log(cveData)
            }
            // Vérifier si le CVE existe déjà
            const existingCve = await Cve.findOne({
                'cveMetadata.cveId': cveData.cveMetadata.cveId
            });

            if (existingCve) {
                console.log(`Le CVE ${cveData.cveMetadata.cveId} existe déjà, mise à jour en cours...`);
                // Mettre à jour le CVE existant
                Object.assign(existingCve, cveData);
                return await existingCve.save();
            }


            // Créer et sauvegarder un nouveau CVE
            const newCve = new Cve(cveData);
            console.log(cveFactory.mapData(cveData));
            process.exit(1)
            return await newCve.save();
        } catch (error) {
            console.error('Erreur dans le service CVE:', error);
            process.exit(1)
            throw error;
        }
    },


};

export default cveService;