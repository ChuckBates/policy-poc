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
	input.resource.action in user_permissions
	location_is_valid
	product_type_is_valid
	company_party_is_valid
	pss_right_is_valid
}

allow if {
	input.resource.requestType = "generate_query"
	input.resource.action in permission_sets["nominations"]
	input.resource.action in user_permissions
	pss_right_is_valid
	allowedNominations[x]
}

allow  if {
	input.resource.requestType = "generate_query"
	input.resource.action in permission_sets["tickets"]
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
principal := principals[input.resource.principal]

user_permissions contains permission if {
	some inherited_permission in inherited_permissions
	some permission in permissions_by_role[inherited_permission.role].valid_actions
	permission in subscriber_permissions
}

subscriber_permissions contains subscriber_permission if {
    some subscriber in input.resource.subscribers
	some subscriber_permission in subscribers[subscriber].permissions
}

inherited_permissions contains permission if {
	some permission in principal.permissions
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
	some company_permission in companies[permission.company].permissions
    some subscriber in input.resource.subscribers
	company_permission.subscriber = subscriber
	some productType in company_permission.productTypes
}

inherited_locations contains location if {
	some permission in inherited_permissions
	some company_permission in companies[permission.company].permissions
    some subscriber in input.resource.subscribers
	company_permission.subscriber = subscriber
	some location in company_permission.locations
}

# Double policy variable assignment is Rego's way of doing a logical OR
pss_right_is_valid if permissions[input.resource.action].pss_right == ""
pss_right_is_valid if permissions[input.resource.action].pss_right in principal.pss_rights

required_company_party := permissions[input.resource.action].companyParty
company_party_is_valid if required_company_party == "*"
company_party_is_valid if {
    required_company_party == input.resource.companyParties[i]
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
principals := {
    "bob": {
        "permissions": [
			{
                "role": "companyAdministrator",
                "company": "EXN",
                "subscriber": "CPL",
                "locations": [
                    "DVD",
					"SAN",
					"STL"
                ],
                "productTypes": [
                    "GAS",
					"JET"
                ]
            },
            {
                "role": "scheduler",
                "company": "EXN",
                "subscriber": "CPL",
                "locations": [
                    "*"
                ],
                "productTypes": [
                    "*"
                ]
            }            
        ],
        "pss_rights": [
            "pss_nomination_create"
        ]
    },
	"alice": {
		"permissions": [
			{
				"role": "inspector",
				"company": "P66",
				"subscriber": "KMO",
				"locations": [
					"DVD"
				],
				"productTypes": [
					"GAS"
				]
			}           
		],
		"pss_rights": []
	}
}

companies := {
    "EXN": {
        "permissions": [
            {
                "subscriber": "CPL",
                "role": "scheduler",
                "locations": [
                    "DVD",
                    "SAN"
                ],
                "productTypes": [
                    "GAS",
                    "JET"
                ]
            },
            {
                "subscriber": "CPL",
                "role": "compayAdministrator",
                "locations": [
                    "DVD",
                    "SAN"
                ],
                "productTypes": [
                    "GAS",
                    "JET"
                ]
            }
        ]
    },
	"P66": {
		"permissions": [
			{
				"subscriber": "KMO",
				"role": "inspector",
				"locations": [
					"DVD"
				],
				"productTypes": [
					"GAS"
				]
			}
		]
	}
}

permissions_by_role := {
  "scheduler": {
    "valid_actions": [
      "nomination_create",
      "nomination_edit",
      "nomination_view",
      "ticket_create",
      "ticket_edit",
      "ticket_view"
    ]
  },
  "companyAdministrator": {
    "valid_actions": [
	  "nomination_subscriber_confirm",
      "nomination_tankage_confirm",
      "nomination_create",
      "nomination_edit",
      "nomination_view",
      "ticket_create",
      "ticket_edit",
      "ticket_view"
    ]
  },
  "pipelineEmployee": {
    "valid_actions": [
      "nomination_create",
      "nomination_edit",
      "nomination_view",
      "ticket_create",
      "ticket_edit",
      "ticket_view"
    ]
  },
  "inspector": {
    "valid_actions": [
      "nomination_view",
      "ticket_view"
    ]
  }
}

subscribers := {
    "CPL": {
        "permissions": [
			"nomination_subscriber_confirm",
            "nomination_tankage_confirm",
            "nomination_create",
            "nomination_edit",
            "nomination_view",
            "ticket_create",
            "ticket_edit",
            "ticket_view"
        ]
    },
	"KMO": {
		"permissions": [
			"ticket_create",
			"ticket_edit",
			"ticket_view"
		]
	}
}

permissions := {
	"admin_add_application": {},
    "nomination_create": {
        "pss_right": "pss_nomination_create",
        "companyParty": "shipper"
    },
    "nomination_edit": {
        "pss_right": "",
        "companyParty": "shipper"
    },
    "nomination_subscriber_confirm": {
        "pss_right": "pss_nomination_subscriber_confirm",
        "companyParty": "carrier"
    },
    "nomination_supCon_confirm": {
        "pss_right": "",
        "companyParty": "supCon"
    },
    "nomination_tankage_confirm": {
        "pss_right": "",
        "companyParty": "tankage"
    },
    "nomination_view": {
        "pss_right": "",
        "companyParty": "*"
    },
    "ticket_create": {
        "pss_right": "",
        "companyParty": "subscriber"
    },
    "ticket_edit": {
        "pss_right": "",
        "companyParty": "subscriber"
    },
    "ticket_view": {
        "pss_right": "",
        "companyParty": "*"
    }
}

permission_sets := {
	"nominations": [
		"nomination_create",
		"nomination_edit",
		"nomination_subscriber_confirm",
		"nomination_supCon_confirm",
		"nomination_tankage_confirm",
		"nomination_view",
	],
	"tickets": [
		"ticket_create",
		"ticket_edit",
		"ticket_view"
	]
}
