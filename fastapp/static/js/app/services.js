var baseServices = angular.module('baseServices', ['ngResource', 'ngCookies']);

// bases
baseServices.factory('Bases', ['$resource', function($resource) {
	return $resource('/fastapp/api/base/', {}, {
		all: {
			method: 'GET',
			isArray: true
		},
		create: {
			method: 'POST',
			params: {
				baseId: 'baseId'
			},
			isArray: false
		}
	});
}]);
baseServices.factory('Base', ['$resource', '$cookies', function($resource,
	$cookies) {
	return $resource('/fastapp/api/base/:name/', {}, {
		get: {
			method: 'GET',
			params: {
				name: 'name'
			},
			isArray: false
		},
		update: {
			method: 'PUT',
			params: {
				name: 'name'
			},
			isArray: false
		},
		start: {
			method: 'POST',
			params: {
				name: 'name'
			},
			isArray: false,
			headers: {
				'X-CSRFToken': $cookies.csrftoken
			},
			url: '/fastapp/api/base/:name/start'
		},
		stop: {
			method: 'POST',
			params: {
				name: 'name'
			},
			isArray: false,
			headers: {
				'X-CSRFToken': $cookies.csrftoken
			},
			url: '/fastapp/api/base/:name/stop'
		},
		restart: {
			method: 'POST',
			params: {
				name: 'name'
			},
			isArray: false,
			headers: {
				'X-CSRFToken': $cookies.csrftoken
			},
			url: '/fastapp/api/base/:name/restart'
		},
		destroy: {
			method: 'POST',
			params: {
				name: 'name'
			},
			isArray: false,
			headers: {
				'X-CSRFToken': $cookies.csrftoken
			},
			url: '/fastapp/api/base/:name/destroy'
		},
		transport: {
			method: 'POST',
			params: {
				name: 'name'
			},
			isArray: false,
			headers: {
				'X-CSRFToken': $cookies.csrftoken
			},
			url: '/fastapp/api/base/:name/transport'
		},
	});
}]);

// apy
baseServices.factory('Apy', ['$resource', '$cookies', function($resource,
	$cookies) {
	return $resource('/fastapp/api/base/:name/apy', {}, {
		all: {
			method: 'GET',
			params: {
				name: 'name'
			},
			isArray: true
		},
		create: {
			method: 'POST',
			params: {
				name: 'name'
			},
			isArray: false,
			headers: {
				'X-CSRFToken': $cookies.csrftoken
			}
		},
	});
}]);

// apy
baseServices.factory('PublicApy', ['$resource', '$cookies', function($resource,
	$cookies) {
	return $resource('/fastapp/api/public-apy', {}, {
		all: {
			method: 'GET',
			isArray: true
		}
	});
}]);

// apy
baseServices.factory('Apy1', ['$resource', '$cookies', function($resource,
	$cookies) {
	return $resource('/fastapp/api/base/:name/apy/:id', {}, {
		update: {
			method: 'PUT',
			params: {
				name: 'name',
				id: 'id'
			},
			isArray: false,
			headers: {
				'X-CSRFToken': $cookies.csrftoken
			}
		},
		get: {
			method: 'GET',
			params: {
				name: 'name',
				id: 'id'
			},
			isArray: false,
			headers: {
				'X-CSRFToken': $cookies.csrftoken
			}
		},
		delete: {
			method: 'DELETE',
			params: {
				name: 'name',
				id: 'id'
			},
			isArray: false,
			headers: {
				'X-CSRFToken': $cookies.csrftoken
			}
		},
		clone: {
			method: 'POST',
			params: {
				baseId: 'id',
				id: 'id'
			},
			isArray: false,
			headers: {
				'X-CSRFToken': $cookies.csrftoken
			},
			url: '/fastapp/api/base/:baseId/apy/:id/clone'
		},
	});
}]);

// settings
baseServices.factory('Settings', ['$resource', '$cookies', function($resource,
	$cookies) {
	return $resource('/fastapp/api/base/:name/setting', {}, {
		all: {
			method: 'GET',
			params: {
				name: 'name'
			},
			isArray: true
		},
		create: {
			method: 'POST',
			params: {
				name: 'name'
			},
			isArray: false,
			headers: {
				'X-CSRFToken': $cookies.csrftoken
			}
		},
	});
}]);
baseServices.factory('Setting', ['$resource', '$cookies', function($resource,
	$cookies) {
	return $resource('/fastapp/api/base/:name/setting/:id', {}, {
		update: {
			method: 'PUT',
			params: {
				name: 'name',
				id: 'id'
			},
			isArray: false,
			headers: {
				'X-CSRFToken': $cookies.csrftoken
			}
		},
		delete: {
			method: 'DELETE',
			params: {
				name: 'name',
				id: 'id'
			},
			isArray: false,
			headers: {
				'X-CSRFToken': $cookies.csrftoken
			}
		},
	});
}]);
/*
baseServices.factory('Settings', ['$resource', function($resource){
    return $resource('/fastapp/api/base/:baseId/setting\\/', {}, {
      create: {method:'POST', params:{baseId: 'id', key: '@key', value: '@value'}, isArray:false}
   });
}]);
baseServices.factory('Settings', ['$resource', function($resource){
    return $resource('api/:baseId/setting/:settingId\\/', {}, {
      save: {method:'POST', params:{baseId: 'id', settingId: 'id'}, isArray:false}
   });
}]);
*/

baseServices.factory('TransportEndpoints', ['$resource', function($resource) {
	return $resource('/fastapp/api/transportendpoints/:id/', null, {
		'update': {
			method: 'PUT'
		}
	});
}]);
