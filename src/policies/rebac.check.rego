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
	input.resource.requestType == "evaluate"
	input.resource.action in user_permitted_actions
	# location_is_valid
	# product_type_is_valid
	# company_party_is_valid
	# pss_right_is_valid
}

# nomination_action_set_relations := ds.object({
#     "object_type": "action_set",
#     "object_id": "nominations",
#     "with_relations": true
# }).relations
# nomination_action_set := [object_id | nomination_action_set_relations[i].object_type = "action"; object_id := nomination_action_set_relations[i].object_id]

# ticket_action_set_relations := ds.object({
#     "object_type": "action_set",
#     "object_id": "tickets",
#     "with_relations": true
# }).relations
# ticket_action_set := [object_id | ticket_action_set_relations[i].object_type = "action"; object_id := ticket_action_set_relations[i].object_id]

# allow if {
# 	input.resource.requestType == "generate_query"
# 	input.resource.action in nomination_action_set
# 	input.resource.action in user_permissions 
# 	pss_right_is_valid
# 	allowedNominations[x]
# }

# allow  if {
# 	input.resource.requestType == "generate_query"
# 	input.resource.action in ticket_action_set
# 	input.resource.action in user_permissions 
# 	pss_right_is_valid
# 	allowedTickets[x]
# }

# allowedNominations[x] if {
# 	data.nominations[x].location = inherited_locations[_]
# 	data.nominations[x].productType = inherited_product_types[_]
# 	data.nominations[x].company = inherited_companies[_]
# 	data.nominations[x].subscriber = inherited_subscribers[_]
# }

# allowedTickets[x] if {
# 	data.tickets[x].location = inherited_locations[_]
# 	data.tickets[x].productType = inherited_product_types[_]
# 	data.tickets[x].company = inherited_companies[_]
# 	data.tickets[x].subscriber = inherited_subscribers[_]
# }

#
# Policy rules and variables
#
principal := retrieve_directory_object("user", input.resource.principal)
principal_user_permission_ids := get_object_relations_as_properties(principal, "user_permission")
# principal := ds.object({
#     "object_type": "user",
#     "object_id": input.resource.principal,
#     "with_relations": true
# })
# principal_user_permissions := [object_id | principal.relations[i].object_type = "user_permission"; object_id := principal.relations[i].object_id]
# principal_pss_rights := [object_id | principal.relations[i].object_type = "pss_right"; object_id := principal.relations[i].object_id]

user_permitted_actions contains action if {
	some inherited_permission_id in inherited_permissions
    inherited_permission := retrieve_directory_object("user_permission", inherited_permission_id)
    inherited_permission_role_ids := get_object_relations_as_properties(inherited_permission, "role")
    inherited_permission_role := retrieve_directory_object("role", inherited_permission_role_ids[0])
    inherited_permission_role_actions := get_object_relations_as_properties(inherited_permission_role, "action")
    # inherited_permission := ds.object({
    #     "object_type": "user_permission",
    #     "object_id": inherited_permission_id,
    #     "with_relations": true
    # })
    # permission_role := [object_id | inherited_permission.relations[i].object_type = "role"; object_id := inherited_permission.relations[i].object_id][0]
    # role := ds.object({
    #     "object_type": "role",
    #     "object_id": permission_role,
    #     "with_relations": true
    # })
    # role_actions := [object_id | role.relations[i].object_type = "action"; object_id := role.relations[i].object_id]
	some action in inherited_permission_role_actions
	action in subscriber_permitted_actions
}

subscriber_permitted_actions contains subscriber_permitted_action if {
    some input_subscriber in input.resource.subscribers
    subscriber := retrieve_directory_object("subscriber", input_subscriber)
    subscriber_action_set_ids := get_object_relations_as_properties(subscriber, "action_set")
    # subscriber := ds.object({
    #     "object_type": "subscriber",
    #     "object_id": input_subscriber,
    #     "with_relations": true
    # })
    # subscriber_action_sets := [object_id | subscriber.relations[i].object_type = "action_set"; object_id := subscriber.relations[i].object_id]
    some subscriber_action_set_id in subscriber_action_set_ids
    subscriber_action_set := retrieve_directory_object("action_set", subscriber_action_set_id)
    subscriber_action_set_actions := get_object_relations_as_properties(subscriber_action_set, "action")
    # action_set := ds.object({
    #     "object_type": "action_set",
    #     "object_id": subscriber_action_set,
    #     "with_relations": true
    # })
    # actions := [object_id | action_set.relations[i].object_type = "action"; object_id := action_set.relations[i].object_id]
    some subscriber_permitted_action in subscriber_action_set_actions
}

inherited_permissions contains permission_id if {
	some user_permission_id in principal_user_permission_ids
    user_permission := retrieve_directory_object("user_permission", user_permission_id)
    user_permission_subscriber_ids := get_object_relations_as_properties(user_permission, "subscriber")
    user_permission_company_ids := get_object_relations_as_properties(user_permission, "company")
    # user_permission := ds.object({
    #     "object_type": "user_permission",
    #     "object_id": user_permission_id,
    #     "with_relations": true
    # })
    # permission_subscriber := [object_id | permission.relations[i].object_type = "subscriber"; object_id := permission.relations[i].object_id][0]
    # permission_company := [object_id | permission.relations[i].object_type = "company"; object_id := permission.relations[i].object_id][0]
	user_permission_subscriber_ids[0] in input.resource.subscribers
	user_permission_company_ids[0] in input.resource.companies
    permission_id = user_permission.id
}

retrieve_directory_object(object_type, object_id) := object if {
    object := ds.object({
        "object_type": object_type,
        "object_id": object_id,
        "with_relations": true
    })
}

get_object_relations_as_properties(object, relation_id) := object_property if {
    object_property := [object_id | object.relations[i].object_type = relation_id; object_id := object.relations[i].object_id]
}

# inherited_companies contains company if {
# 	some permission_id in inherited_permissions
#     permission := ds.object({
#         "object_type": "user_permission",
#         "object_id": permission_id,
#         "with_relations": true
#     })
#     permission_company := [object_id | permission.relations[i].object_type = "company"; object_id := permission.relations[i].object_id][0]
# 	company = permission_company
# }

# inherited_subscribers contains subscriber if {
# 	some permission_id in inherited_permissions
#     permission := ds.object({
#         "object_type": "user_permission",
#         "object_id": permission_id,
#         "with_relations": true
#     })
#     permission_subscriber := [object_id | permission.relations[i].object_type = "subscriber"; object_id := permission.relations[i].object_id][0]
# 	subscriber = permission_subscriber
# }

# inherited_product_types contains productType if {
# 	some permission_id in inherited_permissions
#     permission := ds.object({
#         "object_type": "user_permission",
#         "object_id": permission_id,
#         "with_relations": true
#     })
#     permission_company := [object_id | permission.relations[i].object_type = "company"; object_id := permission.relations[i].object_id][0]
#     company := ds.object({
#         "object_type": "company",
#         "object_id": permission_company,
#         "with_relations": true
#     })
#     company_permissions := [object_id | company.relations[i].object_type = "company_permission"; object_id := company.relations[i].object_id]

# 	some company_permission_id in company_permissions
#     some subscriber in input.resource.subscribers
#     company_permission := ds.object({
#         "object_type": "company_permission",
#         "object_id": company_permission_id,
#         "with_relations": true
#     })
#     company_permission_subscriber := [object_id | company_permission.relations[i].object_type = "subscriber"; object_id := company_permission.relations[i].object_id]
# 	company_permission_subscriber = subscriber
#     company_permission_productTypes := [object_id | company_permission.relations[i].object_type = "product_type"; object_id := company_permission.relations[i].object_id]
# 	some productType in company_permission_productTypes
# }

# inherited_locations contains location if {
# 	some permission_id in inherited_permissions
#     permission := ds.object({
#         "object_type": "user_permission",
#         "object_id": permission_id,
#         "with_relations": true
#     })
#     permission_company := [object_id | permission.relations[i].object_type = "company"; object_id := permission.relations[i].object_id][0]
#     company := ds.object({
#         "object_type": "company",
#         "object_id": permission_company,
#         "with_relations": true
#     })
#     company_permissions := [object_id | company.relations[i].object_type = "company_permission"; object_id := company.relations[i].object_id]

# 	some company_permission_id in company_permissions
#     some subscriber in input.resource.subscribers
#     company_permission := ds.object({
#         "object_type": "company_permission",
#         "object_id": company_permission_id,
#         "with_relations": true
#     })
#     company_permission_subscriber := [object_id | company_permission.relations[i].object_type = "subscriber"; object_id := company_permission.relations[i].object_id]
# 	company_permission_subscriber = subscriber
#     company_permission_locations := [object_id | company_permission.relations[i].object_type = "location"; object_id := company_permission.relations[i].object_id]
# 	some location in company_permission_locations
# }

# action := ds.object({
#     "object_type": "action",
#     "object_id": input.resource.action,
#     "with_relations": true
# })
# action_pss_right := action.properties.pss_right
# action_company_party := action.properties.companyParty

# Double policy variable assignment is Rego's way of doing a logical OR
# pss_right_is_valid if action_pss_right == ""
# pss_right_is_valid if action_pss_right in principal_pss_rights

# company_party_is_valid if action_company_party == "*"
# company_party_is_valid if {
#     action_company_party == input.resource.companyParties[i]
#     input.resource.companies[i] in inherited_companies
# }

# location_is_valid if "ALL" in inherited_locations
# location_is_valid if {
# 	some location in input.resource.locations
#     location in inherited_locations
# }

# product_type_is_valid if "ALL" in inherited_product_types
# product_type_is_valid if {
# 	some productType in input.resource.productTypes
#     productType in inherited_product_types
# }

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
