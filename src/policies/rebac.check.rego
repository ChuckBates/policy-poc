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
	location_is_valid
	product_type_is_valid
	company_party_is_valid
	pss_right_is_valid
}

nomination_action_set := retrieve_directory_object("action_set", "nominations")
nomination_action_ids := get_object_relations_as_properties(nomination_action_set, "action")

ticket_action_set := retrieve_directory_object("action_set", "tickets")
ticket_action_ids := get_object_relations_as_properties(ticket_action_set, "action")

allow if {
	input.resource.requestType == "generate_query"
	input.resource.action in nomination_action_ids
	input.resource.action in user_permitted_actions 
	pss_right_is_valid
	allowedNominations[x]
}

allow  if {
	input.resource.requestType == "generate_query"
	input.resource.action in ticket_action_ids
	input.resource.action in user_permitted_actions 
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
principal := retrieve_directory_object("user", input.resource.principal)
principal_user_permission_ids := get_object_relations_as_properties(principal, "user_permission")
principal_user_pss_rights := get_object_relations_as_properties(principal, "pss_right")

user_permitted_actions contains action if {
	some inherited_permission_id in inherited_permissions
    inherited_permission := retrieve_directory_object("user_permission", inherited_permission_id)
    inherited_permission_role_ids := get_object_relations_as_properties(inherited_permission, "role")
    inherited_permission_role := retrieve_directory_object("role", inherited_permission_role_ids[0])
    inherited_permission_role_actions := get_object_relations_as_properties(inherited_permission_role, "action")
	some action in inherited_permission_role_actions
	action in subscriber_permitted_actions
}

subscriber_permitted_actions contains subscriber_permitted_action if {
    some input_subscriber in input.resource.subscribers
    subscriber := retrieve_directory_object("subscriber", input_subscriber)
    subscriber_action_set_ids := get_object_relations_as_properties(subscriber, "action_set")
    some subscriber_action_set_id in subscriber_action_set_ids
    subscriber_action_set := retrieve_directory_object("action_set", subscriber_action_set_id)
    subscriber_action_set_actions := get_object_relations_as_properties(subscriber_action_set, "action")
    some subscriber_permitted_action in subscriber_action_set_actions
}

inherited_permissions contains permission_id if {
	some user_permission_id in principal_user_permission_ids
    user_permission := retrieve_directory_object("user_permission", user_permission_id)
    user_permission_subscriber_ids := get_object_relations_as_properties(user_permission, "subscriber")
    user_permission_company_ids := get_object_relations_as_properties(user_permission, "company")
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

inherited_companies contains company if {
	some inherited_permission_id in inherited_permissions
    inherited_permission := retrieve_directory_object("user_permission", inherited_permission_id)
    inherited_permission_company_ids := get_object_relations_as_properties(inherited_permission, "company")
	company = inherited_permission_company_ids[0]
}

inherited_subscribers contains subscriber if {
	some inherited_permission_id in inherited_permissions
    inherited_permission := retrieve_directory_object("user_permission", inherited_permission_id)
    inherited_permission_subscriber_ids := get_object_relations_as_properties(inherited_permission, "subscriber")
	subscriber = inherited_permission_subscriber_ids[0]
}

inherited_product_types contains productType if {
	some inheritied_permission_id in inherited_permissions
    inherited_permission := retrieve_directory_object("user_permission", inheritied_permission_id)
    inherited_permission_productTypes := get_object_relations_as_properties(inherited_permission, "productType")
	some productType in inherited_permission_productTypes
}

inherited_locations contains location if {
	some inheritied_permission_id in inherited_permissions
    inherited_permission := retrieve_directory_object("user_permission", inheritied_permission_id)
    inherited_permission_locations := get_object_relations_as_properties(inherited_permission, "location")
	some location in inherited_permission_locations
}

action := retrieve_directory_object("action", input.resource.action)
action_pss_right := action.properties.pss_right
action_company_party := action.properties.companyParty

# Double policy variable assignment is Rego's way of doing a logical OR
pss_right_is_valid if action_pss_right == ""
pss_right_is_valid if action_pss_right in principal_user_pss_rights

company_party_is_valid if action_company_party == "*"
company_party_is_valid if {
    action_company_party == input.resource.companyParties[i]
    input.resource.companies[i] in inherited_companies
}

location_is_valid if "ALL" in inherited_locations
location_is_valid if {
	some location in input.resource.locations
    location in inherited_locations
}

product_type_is_valid if "ALL" in inherited_product_types
product_type_is_valid if {
	some productType in input.resource.productTypes
    productType in inherited_product_types
}
