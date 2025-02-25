package rebac.check

import rego.v1

default allow := false

# Policies to be enforced:
# 1. A user can only perform actions that they have inherited the permissions for
# 2. A user can only perform actions on locations, product types, and companies that they have inherited permissions for
# 3. A user can only perform actions when a company party is required if they have the required inherited permissions
# 4. A user can only perform actions if they have the required PSS right if defined
# 5. A user can generate queries for nominations or tickets if they have the required permissions, locations, product types, and companies
#
# Rego documentations: https://www.openpolicyagent.org/docs/latest/policy-language/
#

#
# Policy enforcement
#
allow if {
	input.resource.requestType = "evaluate"
    print("user_permissions: ", user_permissions)
	input.resource.action in user_permissions
    print("location_is_valid: ", location_is_valid)
	location_is_valid
    print("product_type_is_valid: ", product_type_is_valid)
	product_type_is_valid
    print("company_party_is_valid: ", company_party_is_valid)
	company_party_is_valid
    print("pss_right_is_valid: ", pss_right_is_valid)
	pss_right_is_valid
}

nomination_action_set_relations := ds.object({
    "object_type": "action_set",
    "object_id": "nominations",
    "with_relations": true
}).relations
nomination_action_set := [object_id | nomination_action_set_relations[i].object_type = "action"; object_id := nomination_action_set_relations[i].object_id]

ticket_action_set_relations := ds.object({
    "object_type": "action_set",
    "object_id": "tickets",
    "with_relations": true
}).relations
ticket_action_set := [object_id | ticket_action_set_relations[i].object_type = "action"; object_id := ticket_action_set_relations[i].object_id]

allow if {
	input.resource.requestType = "generate_query"
	input.resource.action in nomination_action_set
	input.resource.action in user_permissions 
	pss_right_is_valid
	allowedNominations[x]
}

allow  if {
	input.resource.requestType = "generate_query"
	input.resource.action in ticket_action_set
	input.resource.action in user_permissions 
	pss_right_is_valid
	allowedTickets[x]
}

allowedNominations[x] if {
	data.nominations[x].location = inherited_locations[_]
	data.nominations[x].productType = inherited_product_types[_]
	data.nominations[x].company = inherited_companies[_]
	data.nominations[x].subscriber = inherited_subscribers[_]
}

allowedTickets[x] if {
	data.tickets[x].location = inherited_locations[_]
	data.tickets[x].productType = inherited_product_types[_]
	data.tickets[x].company = inherited_companies[_]
	data.tickets[x].subscriber = inherited_subscribers[_]
}

#
# Policy rules and variables
#
principal := ds.object({
    "object_type": "user",
    "object_id": input.resource.principal,
    "with_relations": true
})
principal_user_permissions := [object_id | principal.relations[i].object_type = "user_permission"; object_id := principal.relations[i].object_id]
principal_pss_rights := [object_id | principal.relations[i].object_type = "pss_right"; object_id := principal.relations[i].object_id]

user_permissions contains permission if {
	some inherited_permission in inherited_permissions
    role := ds.object({
        "object_type": "role",
        "object_id": inherited_permission.role,
        "with_relations": true
    })
    role_actions := [object_id | role.relations[i].object_type = "action"; object_id := role.relations[i].object_id]
	some permission in role_actions
	permission in subscriber_permissions
}

subscriber_permissions contains subscriber_permission if {
    some input_subscriber in input.resource.subscribers
    subscriber := ds.object({
        "object_type": "subscriber",
        "object_id": input_subscriber,
        "with_relations": true
    })
    subscriber_permissions := [object_id | subscriber.relations[i].object_type = "subscriber_permission"; object_id := subscriber.relations[i].object_id]
	some subscriber_permission in subscriber_permissions
}

inherited_permissions contains permission if {
	some permission in principal_user_permissions
	permission.subscriber in input.resource.subscribers
	permission.company in input.resource.companies
}

inherited_companies contains company if {
	some permission in inherited_permissions
	company = permission.company
}

inherited_subscribers contains subscriber if {
	some permission in inherited_permissions
	subscriber = permission.subscriber
}

inherited_product_types contains productType if {
	some permission in inherited_permissions
    company := ds.object({
        "object_type": "company",
        "object_id": permission.company,
        "with_relations": true
    })
    company_permissions := [object_id | company.relations[i].object_type = "company_permission"; object_id := company.relations[i].object_id]

	some company_permission in company_permissions
    some subscriber in input.resource.subscribers
	company_permission.subscriber = subscriber
	some productType in company_permission.productTypes
}

inherited_locations contains location if {
	some permission in inherited_permissions
    company := ds.object({
        "object_type": "company",
        "object_id": permission.company,
        "with_relations": true
    })
    company_permissions := [object_id | company.relations[i].object_type = "company_permission"; object_id := company.relations[i].object_id]

	some company_permission in company_permissions
    some subscriber in input.resource.subscribers
	company_permission.subscriber = subscriber
	some location in company_permission.locations
}

action := ds.object({
    "object_type": "action",
    "object_id": input.resource.action,
    "with_relations": true
})
action_pss_right := action.properties.pss_right
action_company_party := action.properties.companyParty

# Double policy variable assignment is Rego's way of doing a logical OR
pss_right_is_valid if action_pss_right == ""
pss_right_is_valid if action_pss_right in principal_pss_rights

company_party_is_valid if action_company_party == "*"
company_party_is_valid if {
    action_company_party == input.resource.companyParties[i]
    input.resource.companies[i] in inherited_companies
}

location_is_valid if "*" in inherited_locations
location_is_valid if {
	some location in input.resource.locations
    location in inherited_locations
}

product_type_is_valid if "*" in inherited_product_types
product_type_is_valid if {
	some productType in input.resource.productTypes
    productType in inherited_product_types
}

#
# Backing data (static for a POC, will by externalized in a real-world scenario)
#
# principals := {
#     "bob": {
#         "permissions": [
# 			{
#                 "role": "companyAdministrator",
#                 "company": "EXN",
#                 "subscriber": "CPL",
#                 "locations": [
#                     "DVD",
# 					"SAN",
# 					"STL"
#                 ],
#                 "productTypes": [
#                     "GAS",
# 					"JET"
#                 ]
#             },
#             {
#                 "role": "scheduler",
#                 "company": "EXN",
#                 "subscriber": "CPL",
#                 "locations": [
#                     "*"
#                 ],
#                 "productTypes": [
#                     "*"
#                 ]
#             }            
#         ],
#         "pss_rights": [
#             "pss_nomination_create"
#         ]
#     },
# 	"alice": {
# 		"permissions": [
# 			{
# 				"role": "inspector",
# 				"company": "P66",
# 				"subscriber": "KMO",
# 				"locations": [
# 					"DVD"
# 				],
# 				"productTypes": [
# 					"GAS"
# 				]
# 			}           
# 		],
# 		"pss_rights": []
# 	}
# }

# companies := {
#     "EXN": {
#         "permissions": [
#             {
#                 "subscriber": "CPL",
#                 "role": "scheduler",
#                 "locations": [
#                     "DVD",
#                     "SAN"
#                 ],
#                 "productTypes": [
#                     "GAS",
#                     "JET"
#                 ]
#             },
#             {
#                 "subscriber": "CPL",
#                 "role": "compayAdministrator",
#                 "locations": [
#                     "DVD",
#                     "SAN"
#                 ],
#                 "productTypes": [
#                     "GAS",
#                     "JET"
#                 ]
#             }
#         ]
#     },
# 	"P66": {
# 		"permissions": [
# 			{
# 				"subscriber": "KMO",
# 				"role": "inspector",
# 				"locations": [
# 					"DVD"
# 				],
# 				"productTypes": [
# 					"GAS"
# 				]
# 			}
# 		]
# 	}
# }

# permissions_by_role := {
#   "scheduler": {
#     "valid_actions": [
#       "nomination_create",
#       "nomination_edit",
#       "nomination_view",
#       "ticket_create",
#       "ticket_edit",
#       "ticket_view"
#     ]
#   },
#   "companyAdministrator": {
#     "valid_actions": [
# 	  "nomination_subscriber_confirm",
#       "nomination_tankage_confirm",
#       "nomination_create",
#       "nomination_edit",
#       "nomination_view",
#       "ticket_create",
#       "ticket_edit",
#       "ticket_view"
#     ]
#   },
#   "pipelineEmployee": {
#     "valid_actions": [
#       "nomination_create",
#       "nomination_edit",
#       "nomination_view",
#       "ticket_create",
#       "ticket_edit",
#       "ticket_view"
#     ]
#   },
#   "inspector": {
#     "valid_actions": [
#       "nomination_view",
#       "ticket_view"
#     ]
#   }
# }

# subscribers := {
#     "CPL": {
#         "permissions": [
# 			"nomination_subscriber_confirm",
#             "nomination_tankage_confirm",
#             "nomination_create",
#             "nomination_edit",
#             "nomination_view",
#             "ticket_create",
#             "ticket_edit",
#             "ticket_view"
#         ]
#     },
# 	"KMO": {
# 		"permissions": [
# 			"ticket_create",
# 			"ticket_edit",
# 			"ticket_view"
# 		]
# 	}
# }

# permissions := {
# 	"admin_add_application": {},
#     "nomination_create": {
#         "pss_right": "pss_nomination_create",
#         "companyParty": "shipper"
#     },
#     "nomination_edit": {
#         "pss_right": "",
#         "companyParty": "shipper"
#     },
#     "nomination_subscriber_confirm": {
#         "pss_right": "pss_nomination_subscriber_confirm",
#         "companyParty": "carrier"
#     },
#     "nomination_supCon_confirm": {
#         "pss_right": "",
#         "companyParty": "supCon"
#     },
#     "nomination_tankage_confirm": {
#         "pss_right": "",
#         "companyParty": "tankage"
#     },
#     "nomination_view": {
#         "pss_right": "",
#         "companyParty": "*"
#     },
#     "ticket_create": {
#         "pss_right": "",
#         "companyParty": "subscriber"
#     },
#     "ticket_edit": {
#         "pss_right": "",
#         "companyParty": "subscriber"
#     },
#     "ticket_view": {
#         "pss_right": "",
#         "companyParty": "*"
#     }
# }

# permission_sets := {
# 	"nominations": [
# 		"nomination_create",
# 		"nomination_edit",
# 		"nomination_subscriber_confirm",
# 		"nomination_supCon_confirm",
# 		"nomination_tankage_confirm",
# 		"nomination_view",
# 	],
# 	"tickets": [
# 		"ticket_create",
# 		"ticket_edit",
# 		"ticket_view"
# 	]
# }
