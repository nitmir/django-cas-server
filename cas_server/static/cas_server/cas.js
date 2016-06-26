function cas_login(cas_server_login, service, login_service, callback){
  var url = cas_server_login + "?service=" + encodeURIComponent(service);
  $.ajax({
    type: "GET",
    url,
    beforeSend(request) {
      request.setRequestHeader("X-AJAX", "1");
    },
    xhrFields: {
      withCredentials: true
    },
    success(data, textStatus, request){
      if(data.status === "success"){
        $.ajax({
          type: "GET",
          url: data.url,
          xhrFields: {
            withCredentials: true
          },
          success: callback,
          error(request, textStatus, errorThrown) {},
        });
      } else {
        if(data.detail === "login required"){
          window.location.href = cas_server_login + "?service=" + encodeURIComponent(login_service);
        } else {
          alert("error: " + data.messages[1].message);
        }
      }
    },
    error(request, textStatus, errorThrown) {},
  });
}

function cas_logout(cas_server_logout){
  $.ajax({
    type: "GET",
    url: cas_server_logout,
    beforeSend(request) {
      request.setRequestHeader("X-AJAX", "1");
    },
    xhrFields: {
      withCredentials: true
    },
    error(request, textStatus, errorThrown) {},
    success(data, textStatus, request){
      if(data.status === "error"){
        alert("error: " + data.messages[1].message);
      }
    },
  });
}
