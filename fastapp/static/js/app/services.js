var baseServices = angular.module('baseServices', ['ngResource', 'ngCookies']);
 
// bases
baseServices.factory('Bases', ['$resource', function($resource){
    return $resource('api/base/', {}, {
      all: {method:'GET', isArray:true},
      create: {method:'POST', params:{baseId: 'baseId'}, isArray:false}
   });
 }]);
baseServices.factory('Base', ['$resource', '$cookies', function($resource, $cookies){
    return $resource('api/base/:baseId/', {}, {
      get: {method:'GET', params:{baseId: 'baseId'}, isArray:true},
      update: {method:'PUT', params:{baseId: 'baseId'}, isArray:false},
      start: {method:'POST', params:{baseId: 'baseId'}, isArray:false, headers:{'X-CSRFToken': $cookies.csrftoken}, url:'api/base/:baseId/start\\/'},
      stop: {method:'POST', params:{baseId: 'baseId'}, isArray:false, headers:{'X-CSRFToken': $cookies.csrftoken}, url:'api/base/:baseId/stop\\/'},
   });
 }]);

// apy
baseServices.factory('Apy', ['$resource', '$cookies', function($resource, $cookies){
    return $resource('/fastapp/api/base/:baseId/apy\\/', {}, {
      all: {method:'GET', params:{baseId: 'id'}, isArray:true},
      create: {method:'POST', params:{baseId: 'id'}, isArray:false, headers:{'X-CSRFToken': $cookies.csrftoken}},
   });
}]);

// apy
baseServices.factory('Apy1', ['$resource', '$cookies', function($resource, $cookies){
    return $resource('/fastapp/api/base/:baseId/apy/:id\\/', {}, {
      update: {method:'PUT', params:{baseId: 'id', id: 'id'}, isArray:false, headers:{'X-CSRFToken': $cookies.csrftoken}},
      get: {method:'GET', params:{baseId: 'id', id: 'id'}, isArray:false, headers:{'X-CSRFToken': $cookies.csrftoken}},
      delete: {method:'DELETE', params:{baseId: 'id', id: 'id'}, isArray:false, headers:{'X-CSRFToken': $cookies.csrftoken}},
      clone: {method:'POST', params:{baseId: 'id', id: 'id'}, isArray:false, headers:{'X-CSRFToken': $cookies.csrftoken}, url:'/fastapp/api/base/:baseId/apy/:id/clone\\/'},
      execute: {method:'GET', params:{baseName: 'baseName', name: 'name'}, isArray:false, headers:{'X-CSRFToken': $cookies.csrftoken}, url:'/fastapp/base/:baseName/exec/:name\\/'},
   });
}]);

// settings
baseServices.factory('Settings', ['$resource', '$cookies', function($resource, $cookies){
    return $resource('/fastapp/api/base/:baseId/setting\\/', {}, {
      all: {method:'GET', params:{baseId: 'id'}, isArray:true},
      create: {method:'POST', params:{baseId: 'id'}, isArray:false, headers:{'X-CSRFToken': $cookies.csrftoken}},
   });
}]);
baseServices.factory('Setting', ['$resource', '$cookies', function($resource, $cookies){
    return $resource('/fastapp/api/base/:baseId/setting/:id\\/', {}, {
      update: {method:'PUT', params:{baseId: 'id', id: 'id'}, isArray:false, headers:{'X-CSRFToken': $cookies.csrftoken}},
      delete: {method:'DELETE', params:{baseId: 'id', id: 'id'}, isArray:false, headers:{'X-CSRFToken': $cookies.csrftoken}},
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