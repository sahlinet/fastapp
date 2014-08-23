  function add_client_message(message) {
    data = {};
    data.message = message;
    var now = NDateTime.Now();
    data.datetime = now.ToString("yyyy-MM-dd HH:mm:ss.ffffff");
    data.class = "info";
    data.source = "Client";
    add_message(data);
  }

  function add_message(data) {
    $("div#messages").prepend("<p class='"+data.class+"'>"+data.datetime+" : "+data.source+" : "+data.message+"</p>");
    $("div#messages p").slice(7).remove();
  }


  window.app = angular.module('execApp', ['ngGrid', 'base64', 'ngResource', 'baseServices', 'doowb.angular-pusher', 'angularFileUpload', 'ngCookies', 'ui.bootstrap']).
  config(['PusherServiceProvider',
    function(PusherServiceProvider) {
      PusherServiceProvider
      .setToken(window.pusher_key)
      .setOptions({encrypted: true});
    }
    ]);

  window.app.controller('BasesCtrl', ['$scope', 'Bases', 'Base', 'Apy', '$upload', '$cookies', '$window', function($scope, Bases, Base, Apy, $upload, $cookies, $window) {
    $scope.init = function() {
      var bases = Bases.all(function() {
        angular.forEach(bases, function(base) {
          base.apy_models = Apy.all({'baseId': base.id});
        });
        $scope.bases = bases;
      });
    };

    $scope.cycle_state = function(base) {
      console.log(base);
      if (base.state) {
        Base.stop({baseId: base.id}, base, function(data) {
          console.log(data);
          base.state = false;
        });
      }
      if (! base.state) {
        Base.start({baseId: base.id}, base, function(data) {
          console.log(data);
          base.state = true;
          base.pids = data['pids'];
        });
      }
    };

    $scope.onFileSelect = function($files) {
    //$files: an array of files selected, each file has name, size, and type.
    for (var i = 0; i < $files.length; i++) {
      var file = $files[i];
      $scope.upload = $upload.upload({
        url: '/fastapp/api/base/import/', //upload.php script, node.js route, or servlet url
        //method: 'POST' or 'PUT',
        //headers: {'header-key': 'header-value'},
        //withCredentials: true,
        headers:{'X-CSRFToken': $cookies.csrftoken},
        data: {attachment: $scope.myModelObj, name: $scope.name},
        file: file, // or list of files ($files) for html5 only
        //fileName: 'doc.jpg' or ['1.jpg', '2.jpg', ...] // to modify the name of the file(s)
        // customize file formData name ('Content-Disposition'), server side file variable name. 
        //fileFormDataName: myFile, //or a list of names for multiple files (html5). Default is 'file' 
        // customize how data is added to formData. See #40#issuecomment-28612000 for sample code
        //formDataAppender: function(formData, key, val){}
      }).progress(function(evt) {
        console.log('percent: ' + parseInt(100.0 * evt.loaded / evt.total));
      }).success(function(data, status, headers, config) {
        // file is uploaded successfully
        console.log(data);
        $window.location="/fastapp/"+data.name+"/index/";

      });
      //.error(...)
      //.then(success, error, progress); 
      // access or attach event listeners to the underlying XMLHttpRequest.
      //.xhr(function(xhr){xhr.upload.addEventListener(...)})
    }
    /* alternative way of uploading, send the file binary with the file's content-type.
       Could be used to upload files to CouchDB, imgur, etc... html5 FileReader is needed. 
       It could also be used to monitor the progress of a normal http post/put request with large data*/
    // $scope.upload = $upload.http({...})  see 88#issuecomment-31366487 for sample code.
  };

}]);


  window.app.controller('ExecCtrl', ['$scope', '$http', '$base64', 'Apy', 'Apy1', 'Pusher', function($scope, $http, $base64, Apy, Apy1, Pusher) {
    $scope.new_exec_name = "";
    $scope.apys = [];

    $scope.alerts = [];

    $scope.closeAlert = function(index) {
      $scope.alerts.splice(index, 1);
    };


    $scope.init = function() {
      var apys= Apy.all({'baseId': window.active_base_id}, function() {
        $scope.apys = apys;
        counter=0;

        $scope.apys.map(function(apy) {
          $scope.$watch(apy, function(changed) {
            console.log("changed");
          }, true);
          counter++;
        });
      });

    // setup pusher for listening to counter events
    Pusher.subscribe(window.channel, "counter", function (item) {
      console.log(item);
      $scope.apys.map(function(apy) {
        if (apy.id == item['apy_id']) { apy.counter = item['counter']; }
      });
    });

    Pusher.subscribe(window.channel, 'pusher:subscription_succeeded', function(members) {
      console.log("subscription_succeeded");
      console.log(members);
      add_client_message("Subscription succeeded.");
    });
  };

  Pusher.subscribe(window.channel, 'console_msg', function(data) {
    data.source = "Server";
    add_message(data);
  });

  $scope.blur = function(apy, $event) {
    console.log(event);
    console.log(apy);
    $scope.save(apy);
  };

  $scope.create = function() {
    Apy.create({'baseId': window.active_base_id}, {'name': $scope.new_exec_name}, function(apy) {
      $scope.apys.push(apy);
      $scope.showNewExec = false;
    });
  };

  $scope.save= function(apy) {
    Apy1.update({'baseId': window.active_base_id, 'id': apy.id}, apy).$promise.then(function(data) {
      console.log("saved");
      $scope.alerts.push({ type: 'success', msg: "Exec '"+apy.name+"' saved" } );
    }, function(data) {
      $scope.alerts.push({ type: 'danger', msg: "Exec '"+apy.name+"' not saved" } );
      console.error("error");
      console.error(data);
      angular.forEach(data.data.detail.errors, function(value, key) {
        $scope.alerts.push({ type: 'danger', msg: value.filename+":"+value.lineno+":"+value.col+": "+value.msg} );
      });
      angular.forEach(data.data.detail.warnings, function(value, key) {
        $scope.alerts.push({ type: 'warning', msg: value.filename+":"+value.lineno+":"+value.col+": "+value.msg} );
      });
    });
  };

  $scope.delete= function(apy) {
    //Apy1.update({'baseId': window.active_base_id, 'id': apy.id}, apy);
    Apy1.delete({'baseId': window.active_base_id, 'id': apy.id}, function(data) {
      var indx = $scope.apys.indexOf(apy);
      $scope.apys.splice(indx, 1);
    });

  };

  $scope.clone= function(apy) {
    Apy1.clone({'baseId': window.active_base_id, 'id': apy.id}, apy, function(data) {
      $scope.apys.push(data);
    });
  };

  $scope.execute=function(apy) {
    Apy1.execute({'baseName': window.active_base, 'name': apy.name, 'json':""});
  };

  $scope.printcurl=function(apy) {
    var parser = document.createElement('a');
    parser.href = document.URL;
    add_client_message("user:   curl -u "+window.username+" -H'Cookie: "+document.cookie+"' \""+parser.protocol+"//"+parser.host+"/fastapp/"+window.active_base+"/exec/"+apy.name+"/?json=\"");
    shared_key = window.shared_key_link.split("?")[1];
    add_client_message("anonym: curl \""+parser.protocol+"//"+parser.host+"/fastapp/base/"+window.active_base+"/exec/"+apy.name+"/?json=&"+shared_key+"\"");
  };

  $scope.rename=function($event) {
    new_exec_name = $($event.currentTarget.parentNode.parentNode).find('input').first().val();
    this.apy.name = new_exec_name;
    this.apy.$save();
    //$scope.save(this.apy);
    //$scope.save(this.apy).success(function() {
    //  console.log(this);
    //  console.log($event);
    //  this.show = false;
    //});
};


  /*$scope.$watch('apy.module', function(oldVal,newVal){
    console.log(oldVal);
    console.log(newVal);
    console.log("changed");
  });*/

}]);

  var removeTemplate = '<button type="button" class="btn btn-default btn-xs" ng-click="delete()"><span class="glyphicon glyphicon-remove"></span> Delete</button>';
  window.app.controller('SettingsCtrl', ['$scope', '$http', '$base64', 'Settings', 'Setting', function($scope, $http, $base64, Settings, Setting) {
    $scope.myData = [];
    $scope.gridOptions = {
      data: 'myData',
      selectedItems: [],
      enableSorting: true,
      sortInfo: {fields: ['key', 'value'], directions: ['asc']},
        //enableCellSelection: true,
        enableRowSelection: false,
        enableCellEditOnFocus: false,
        columnDefs: [{field: 'key', displayName: 'Key', enableCellEdit: true, width: 120},
        {field: 'value', displayName:'Value', enableCellEdit: true, editableCellTemplate: '<textarea row="1"  ng-class="\'colt\' + col.index" ng-input="COL_FIELD" ng-model="COL_FIELD" />'},
        {field: 'actions', displayName:'', enableCellEdit: false, cellTemplate: removeTemplate}
        ]
      };

      $scope.init = function() {
        $scope.myData = Settings.all({'baseId': window.active_base_id });
      };

      $scope.addRow = function() {
        $scope.myData.push({key: "key", value: "value"});
      };

      $scope.save = function() {
      // base64 output
      $scope.myData.map(function(item) {
        if (item.id===undefined) {
          new_item = Settings.create({'baseId': window.active_base_id}, item, function() {
            if (new_item['id']!==undefined) {
              item.id = new_item['id'];
            }
          });

        } else {
          Setting.update({'baseId': window.active_base_id, 'id': item.id}, item);
        }
      });
    };

    $scope.delete = function() {
      var index = this.row.rowIndex;
      $scope.gridOptions.selectItem(index, false);
      removed = $scope.myData.splice(index, 1)[0];
      Setting.delete({'baseId': window.active_base_id, 'id': removed.id});
    };
  }]);

  window.app.directive('codemirror', function() {
    return {
      restrict: 'A',
      priority: 2,
      scope: {
        'apy': '=codemirror'
      },
      template: '{{apy.module}}',
      link: function(scope, elem, attrs) {
      //console.log(scope);
      //console.log(scope.apy);
      var myCodeMirror = CodeMirror(function(elt) {
        elem.parent().replaceWith(elt);
      }, {
        value: scope.apy.module,
        mode: {name: "text/x-cython",
        version: 2,
        singleLineStringErrors: false},
          //readOnly: "$window.readyOnly",
          lineNumbers: true,
          indentUnit: 4,
          tabMode: "shift",
          lineWrapping: true,
          indentWithTabs: true,
          matchBrackets: true,
          vimMode: true,
          showCursorWhenSelecting: true
        });
      myCodeMirror.on("blur", function(cm, cmChangeObject){
        console.log("scope.$apply");
        scope.$apply(function() {
          scope.apy.module = myCodeMirror.getValue();
        });
      });
    }
  };
});