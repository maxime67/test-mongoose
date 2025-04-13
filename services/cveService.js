import Cve from '../models/Cve.js';

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
            return await newCve.save();
        } catch (error) {
            console.error('Erreur dans le service CVE:', error);
            throw error;
        }
    },

    /**
     * Récupère un CVE par son ID
     * @param {String} cveId - ID du CVE à récupérer (ex: CVE-2025-32498)
     * @returns {Promise<Object>} - Le CVE trouvé ou null
     */
    async getCveById(cveId) {
        try {
            return await Cve.findOne({ 'cveMetadata.cveId': cveId });
        } catch (error) {
            console.error('Erreur lors de la récupération du CVE:', error);
            throw error;
        }
    },

    /**
     * Récupère tous les CVE
     * @param {Object} filter - Filtres optionnels
     * @param {Number} limit - Nombre max de résultats
     * @returns {Promise<Array>} - Liste des CVE
     */
    async getAllCves(filter = {}, limit = 100) {
        try {
            return await Cve.find(filter).limit(limit);
        } catch (error) {
            console.error('Erreur lors de la récupération des CVE:', error);
            throw error;
        }
    }
};

export default cveService;