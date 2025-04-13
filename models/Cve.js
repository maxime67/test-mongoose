import mongoose from 'mongoose';

const {Schema} = mongoose;

// Schémas de base communs
const TimestampSchema = {
    type: String,
    match: [
        /^(((2000|2400|2800|(19|2[0-9](0[48]|[2468][048]|[13579][26])))-02-29)|(((19|2[0-9])[0-9]{2})-02-(0[1-9]|1[0-9]|2[0-8]))|(((19|2[0-9])[0-9]{2})-(0[13578]|10|12)-(0[1-9]|[12][0-9]|3[01]))|(((19|2[0-9])[0-9]{2})-(0[469]|11)-(0[1-9]|[12][0-9]|30)))T(2[0-3]|[01][0-9]):([0-5][0-9]):([0-5][0-9])(\.[0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})?$/,
        'Format de date/heure invalide. Utilisez ISO 8601/RFC3339'
    ]
};

const UuidSchema = {
    type: String,
    match: [
        /^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-4[0-9A-Fa-f]{3}-[89ABab][0-9A-Fa-f]{3}-[0-9A-Fa-f]{12}$/,
        'Format UUID v4 invalide'
    ]
};

const LanguageSchema = {
    type: String,
    match: [
        /^[A-Za-z]{2,4}([_-][A-Za-z]{4})?([_-]([A-Za-z]{2}|[0-9]{3}))?$/,
        'Code de langue invalide. Utilisez BCP 47'
    ],
    default: 'en'
};

const UriSchema = {
    type: String,
    match: [
        /^(https?|ftp):\/\/[^\s/$.?#].[^\s]*$/i,
        'URI invalide'
    ],
    maxlength: 2048
};

// Schéma pour les médias supportant les descriptions
const SupportingMediaSchema = new Schema({
    type: {
        type: String,
        required: true,
        maxlength: 256
    },
    base64: {
        type: Boolean,
        default: false
    },
    value: {
        type: String,
        required: true,
        maxlength: 16384
    }
}, {_id: false});

// Schéma pour les descriptions
const DescriptionSchema = new Schema({
    lang: LanguageSchema,
    value: {
        type: String,
        required: true,
        maxlength: 4096
    },
    supportingMedia: [SupportingMediaSchema]
}, {_id: false});

// Schéma pour les références
const ReferenceSchema = new Schema({
    url: UriSchema,
    name: {
        type: String,
        maxlength: 512
    },
    tags: [{
        type: String,
        enum: [
            'broken-link',
            'customer-entitlement',
            'exploit',
            'government-resource',
            'issue-tracking',
            'mailing-list',
            'mitigation',
            'not-applicable',
            'patch',
            'permissions-required',
            'media-coverage',
            'product',
            'related',
            'release-notes',
            'signature',
            'technical-description',
            'third-party-advisory',
            'vendor-advisory',
            'vdb-entry'
        ]
    }]
}, {_id: false});

// Schéma pour les types de problèmes
const ProblemTypeDescriptionSchema = new Schema({
    lang: LanguageSchema,
    description: {
        type: String,
        required: true,
        maxlength: 4096
    },
    cweId: {
        type: String,
        match: [/^CWE-[1-9][0-9]*$/, 'Format CWE-ID invalide']
    },
    type: {
        type: String,
        maxlength: 128
    },
    references: [ReferenceSchema]
}, {_id: false});

const ProblemTypeSchema = new Schema({
    descriptions: {
        type: [ProblemTypeDescriptionSchema],
        required: true,
        validate: [arr => arr.length > 0, 'Au moins une description de problème est requise']
    }
}, {_id: false});

// Schéma pour les métriques CVSS
const CvssV31Schema = new Schema({
    version: {
        type: String,
        enum: ['3.1'],
        required: true
    },
    vectorString: {
        type: String,
        required: true,
        match: [
            /^CVSS:3[.]1\/((AV:[NALP]|AC:[LH]|PR:[NLH]|UI:[NR]|S:[UC]|[CIA]:[NLH]|E:[XUPFH]|RL:[XOTWU]|RC:[XURC]|[CIA]R:[XLMH]|MAV:[XNALP]|MAC:[XLH]|MPR:[XNLH]|MUI:[XNR]|MS:[XUC]|M[CIA]:[XNLH])\/)*?(AV:[NALP]|AC:[LH]|PR:[NLH]|UI:[NR]|S:[UC]|[CIA]:[NLH]|E:[XUPFH]|RL:[XOTWU]|RC:[XURC]|[CIA]R:[XLMH]|MAV:[XNALP]|MAC:[XLH]|MPR:[XNLH]|MUI:[XNR]|MS:[XUC]|M[CIA]:[XNLH])$/,
            'Format de vecteur CVSS 3.1 invalide'
        ]
    },
    baseScore: {
        type: Number,
        required: true,
        min: 0,
        max: 10
    },
    baseSeverity: {
        type: String,
        required: true,
        enum: ['NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
    },
    // Paramètres de base
    attackVector: {
        type: String,
        enum: ['NETWORK', 'ADJACENT_NETWORK', 'LOCAL', 'PHYSICAL']
    },
    attackComplexity: {
        type: String,
        enum: ['HIGH', 'LOW']
    },
    privilegesRequired: {
        type: String,
        enum: ['HIGH', 'LOW', 'NONE']
    },
    userInteraction: {
        type: String,
        enum: ['NONE', 'REQUIRED']
    },
    scope: {
        type: String,
        enum: ['UNCHANGED', 'CHANGED']
    },
    confidentialityImpact: {
        type: String,
        enum: ['NONE', 'LOW', 'HIGH']
    },
    integrityImpact: {
        type: String,
        enum: ['NONE', 'LOW', 'HIGH']
    },
    availabilityImpact: {
        type: String,
        enum: ['NONE', 'LOW', 'HIGH']
    },
    // Métriques temporelles (optionnelles)
    exploitCodeMaturity: {
        type: String,
        enum: ['UNPROVEN', 'PROOF_OF_CONCEPT', 'FUNCTIONAL', 'HIGH', 'NOT_DEFINED']
    },
    remediationLevel: {
        type: String,
        enum: ['OFFICIAL_FIX', 'TEMPORARY_FIX', 'WORKAROUND', 'UNAVAILABLE', 'NOT_DEFINED']
    },
    reportConfidence: {
        type: String,
        enum: ['UNKNOWN', 'REASONABLE', 'CONFIRMED', 'NOT_DEFINED']
    },
    temporalScore: {
        type: Number,
        min: 0,
        max: 10
    },
    temporalSeverity: {
        type: String,
        enum: ['NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
    }
}, {_id: false});

// Schéma pour les autres versions de CVSS simplifié (pour éviter la duplication)
const CvssV20Schema = new Schema({
    version: {
        type: String,
        enum: ['2.0'],
        required: true
    },
    vectorString: String,
    baseScore: {
        type: Number,
        required: true,
        min: 0,
        max: 10
    },
    // Autres propriétés CVSS 2.0...
}, {_id: false, strict: false});

const CvssV30Schema = new Schema({
    version: {
        type: String,
        enum: ['3.0'],
        required: true
    },
    vectorString: String,
    baseScore: {
        type: Number,
        required: true,
        min: 0,
        max: 10
    },
    baseSeverity: {
        type: String,
        required: true,
        enum: ['NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
    },
    // Autres propriétés CVSS 3.0...
}, {_id: false, strict: false});

const CvssV40Schema = new Schema({
    version: {
        type: String,
        enum: ['4.0'],
        required: true
    },
    vectorString: String,
    baseScore: {
        type: Number,
        required: true,
        min: 0,
        max: 10
    },
    baseSeverity: {
        type: String,
        required: true,
        enum: ['NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
    },
    // Autres propriétés CVSS 4.0...
}, {_id: false, strict: false});

// Métriques (peut contenir divers formats CVSS)
const MetricSchema = new Schema({
    format: {
        type: String,
        enum: ['CVSS']
    },
    scenarios: [{
        lang: LanguageSchema,
        value: {
            type: String,
            default: 'GENERAL',
            maxlength: 4096
        }
    }],
    cvssV2_0: CvssV20Schema,
    cvssV3_0: CvssV30Schema,
    cvssV3_1: CvssV31Schema,
    cvssV4_0: CvssV40Schema,
    other: {
        type: {
            type: String,
            maxlength: 128
        },
        content: {
            type: Schema.Types.Mixed,
        }
    }
}, {_id: false});

// Schéma pour les gammes de versions
const VersionRangeSchema = new Schema({
    version: {
        type: String,
        required: true,
        maxlength: 1024
    },
    status: {
        type: String,
        required: true,
        enum: ['affected', 'unaffected', 'unknown']
    },
    versionType: {
        type: String,
        maxlength: 128
    },
    lessThan: {
        type: String,
        maxlength: 1024
    },
    lessThanOrEqual: {
        type: String,
        maxlength: 1024
    },
    changes: [{
        at: {
            type: String,
            required: true,
            maxlength: 1024
        },
        status: {
            type: String,
            required: true,
            enum: ['affected', 'unaffected', 'unknown']
        }
    }]
}, {_id: false});

// Schéma pour les produits affectés
const ProductSchema = new Schema({
    vendor: {
        type: String,
        maxlength: 512
    },
    product: {
        type: String,
        maxlength: 2048
    },
    collectionURL: UriSchema,
    packageName: {
        type: String,
        maxlength: 2048
    },
    cpes: [{
        type: String,

        maxlength: 2048
    }],
    modules: [{
        type: String,
        maxlength: 4096
    }],
    programFiles: [{
        type: String,
        maxlength: 1024
    }],
    programRoutines: [{
        name: {
            type: String,
            required: true,
            maxlength: 4096
        }
    }],
    platforms: [{
        type: String,
        maxlength: 1024
    }],
    repo: UriSchema,
    defaultStatus: {
        type: String,
        enum: ['affected', 'unaffected', 'unknown'],
        default: 'unknown'
    },
    versions: [VersionRangeSchema]
}, {_id: false});

// Schéma pour les crédits
const CreditSchema = new Schema({
    lang: LanguageSchema,
    value: {
        type: String,
        required: true,
        maxlength: 4096
    },
    user: UuidSchema,
    type: {
        type: String,
        enum: [
            'finder',
            'reporter',
            'analyst',
            'coordinator',
            'remediation developer',
            'remediation reviewer',
            'remediation verifier',
            'tool',
            'sponsor',
            'other'
        ],
        default: 'finder'
    }
}, {_id: false});

// Schéma pour les timelines
const TimelineSchema = new Schema({
    time: {
        type: TimestampSchema,
    },
    lang: {
        type: LanguageSchema,
    },
    value: {
        type: String,
        required: true,
        maxlength: 4096
    }
}, {_id: false});

// Schéma pour les métadonnées du fournisseur
const ProviderMetadataSchema = new Schema({
    orgId: {
        type: UuidSchema,
    },
    shortName: {
        type: String,
        minlength: 2,
        maxlength: 32
    },
    dateUpdated: TimestampSchema
}, {_id: false});

// Schéma pour le conteneur CNA
const CnaContainerSchema = new Schema({
    providerMetadata: {
        type: ProviderMetadataSchema,
        required: true
    },
    dateAssigned: TimestampSchema,
    datePublic: TimestampSchema,
    title: {
        type: String,
        maxlength: 256
    },
    descriptions: {
        type: [DescriptionSchema],
        required: true,
        validate: [arr => arr.length > 0, 'Au moins une description est requise']
    },
    affected: {
        type: [ProductSchema],
        required: true,
        validate: [arr => arr.length > 0, 'Au moins un produit affecté est requis']
    },
    problemTypes: [ProblemTypeSchema],
    references: {
        type: [ReferenceSchema],
        required: true,
        validate: [arr => arr.length > 0, 'Au moins une référence est requise']
    },
    impacts: [{
        capecId: {
            type: String,
            match: [/^CAPEC-[1-9][0-9]{0,4}$/, 'Format CAPEC-ID invalide']
        },
        descriptions: [DescriptionSchema]
    }],
    metrics: [MetricSchema],
    configurations: [DescriptionSchema],
    workarounds: [DescriptionSchema],
    solutions: [DescriptionSchema],
    exploits: [DescriptionSchema],
    timeline: [TimelineSchema],
    credits: [CreditSchema],
    source: {
        type: Schema.Types.Mixed
    },
    tags: [{
        type: String,
        enum: ['unsupported-when-assigned', 'exclusively-hosted-service', 'disputed']
    }]
}, {_id: false, strict: false});

// Schéma pour les conteneurs ADP
const AdpContainerSchema = new Schema({
    providerMetadata: {
        type: ProviderMetadataSchema,
        required: true
    },
    datePublic: TimestampSchema,
    title: {
        type: String,
        maxlength: 256
    },
    descriptions: [DescriptionSchema],
    affected: [ProductSchema],
    problemTypes: [ProblemTypeSchema],
    references: [ReferenceSchema],
    impacts: [{
        capecId: {
            type: String,
            match: [/^CAPEC-[1-9][0-9]{0,4}$/, 'Format CAPEC-ID invalide']
        },
        descriptions: [DescriptionSchema]
    }],
    metrics: [MetricSchema],
    configurations: [DescriptionSchema],
    workarounds: [DescriptionSchema],
    solutions: [DescriptionSchema],
    exploits: [DescriptionSchema],
    timeline: [TimelineSchema],
    credits: [CreditSchema],
    source: {
        type: Schema.Types.Mixed
    },
    tags: [{
        type: String,
        enum: ['disputed']
    }]
}, {_id: false, strict: false});

// Schéma pour les métadonnées CVE
const CveMetadataSchema = new Schema({
    cveId: {
        type: String,
        match: [/^CVE-[0-9]{4}-[0-9]{4,19}$/, 'Format CVE-ID invalide']
    },
    assignerOrgId: {
        type: UuidSchema,
    },
    assignerShortName: {
        type: String,
        minlength: 2,
        maxlength: 32
    },
    requesterUserId: UuidSchema,
    dateReserved: TimestampSchema,
    datePublished: TimestampSchema,
    dateUpdated: TimestampSchema,
    state: {
        type: String,
        required: true,
        enum: ['PUBLISHED', 'REJECTED']
    },
    serial: {
        type: Number,
        min: 1
    }
}, {_id: false});

// Schéma pour les containers (corriger la structure ici)
const ContainersSchema = new Schema({
    cna: {
        type: CnaContainerSchema,
        required: true
    },
    adp: [AdpContainerSchema]
}, {_id: false});

// Schéma principal pour CVE
const CveSchema = new Schema({
    dataType: {
        type: String,
        required: true,
        enum: ['CVE_RECORD']
    },
    dataVersion: {
        type: String,
        required: true,
        match: [/^5\.(0|[1-9][0-9]*)(\.(0|[1-9][0-9]*))?$/, 'Format de version invalide'],
        default: '5.1.1'
    },
    cveMetadata: {
        type: CveMetadataSchema,
        required: true
    },
    containers: {
        type: ContainersSchema,
        required: true
    }
}, {
    timestamps: true,
    collection: 'cves'
});

// Méthodes pour faciliter l'utilisation (similaires à celles définies dans votre implémentation)
CveSchema.methods.getTitle = function () {
    if (this.containers && this.containers.cna && this.containers.cna.title) {
        return this.containers.cna.title;
    }
    return null;
};

CveSchema.methods.getDescription = function (lang = 'en') {
    if (this.containers && this.containers.cna && this.containers.cna.descriptions) {
        const desc = this.containers.cna.descriptions.find(d => d.lang.startsWith(lang));
        return desc ? desc.value : null;
    }
    return null;
};

CveSchema.methods.getAffectedProducts = function () {
    if (this.containers && this.containers.cna && this.containers.cna.affected) {
        return this.containers.cna.affected;
    }
    return [];
};

CveSchema.methods.getCvssScores = function () {
    const scores = [];
    if (this.containers && this.containers.cna && this.containers.cna.metrics) {
        this.containers.cna.metrics.forEach(metric => {
            if (metric.cvssV2_0) scores.push({version: '2.0', ...metric.cvssV2_0});
            if (metric.cvssV3_0) scores.push({version: '3.0', ...metric.cvssV3_0});
            if (metric.cvssV3_1) scores.push({version: '3.1', ...metric.cvssV3_1});
            if (metric.cvssV4_0) scores.push({version: '4.0', ...metric.cvssV4_0});
        });
    }
    return scores;
};

// Création du modèle
const Cve = mongoose.model('Cve', CveSchema);

export default Cve;