import Product from '../models/Product.js';

/**
 * Extrait et enregistre les produits d'un document CVE
 * @param {Object} cveDocument - Document CVE Mongoose
 * @returns {Promise<Array>} - Liste des produits extraits et enregistrés
 */
const extractAndSaveProducts = async (cveDocument) => {
    try {
        const results = [];

        // Vérifier si le CVE contient des produits affectés
        if (cveDocument.containers &&
            cveDocument.containers.cna &&
            cveDocument.containers.cna.affected &&
            Array.isArray(cveDocument.containers.cna.affected)) {

            // Pour chaque produit affecté listé dans le CVE
            for (const affectedProduct of cveDocument.containers.cna.affected) {
                // Vérifier que les champs obligatoires sont présents
                if (!affectedProduct.vendor || !affectedProduct.product) {
                    console.warn(`Produit sans vendor ou product ignoré dans CVE: ${cveDocument.cveMetadata.cveId}`);
                    continue;
                }

                try {
                    // Utiliser la méthode findOrCreate pour insérer ou mettre à jour le produit
                    // et ajouter directement la référence au CVE
                    const product = await Product.findOrCreate(affectedProduct);

                    // Ajouter une référence au CVE dans le produit en utilisant la méthode corrigée
                    if (product && cveDocument._id) {
                        await product.addCveReference(cveDocument._id);
                    }

                    results.push(product);
                } catch (error) {
                    console.error(`Erreur lors du traitement du produit ${affectedProduct.vendor}/${affectedProduct.product}:`, error);
                }
            }
        }

        return results;
    } catch (error) {
        console.error('Erreur lors de l\'extraction des produits:', error);
        throw error;
    }
};

export default extractAndSaveProducts;