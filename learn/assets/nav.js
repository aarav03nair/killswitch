(function(){
  var pages=[
    ["index.html","Start here",null],
    ["01-big-picture.html","1. The big picture","Foundations"],
    ["02-repo-map.html","2. Repo and folder map",null],
    ["03-contracts.html","3. Contracts: the shared language",null],
    ["04-identity-isolation.html","4. Identity and isolation","The platform, piece by piece"],
    ["05-tick-barrier.html","5. The tick barrier (runtime)",null],
    ["06-gateway.html","6. The gateway (the core)",null],
    ["07-state-outbox.html","7. State store and outbox",null],
    ["08-record-witness-verify.html","8. Record, witness, verify",null],
    ["09-monitor-containment.html","9. Monitor and containment","Reacting to a fault"],
    ["10-taint-recovery.html","10. Taint and recovery",null],
    ["11-world-oracle-score.html","11. World, oracle, scoring","Testing and using it"],
    ["12-cli-demo.html","12. CLI, demo, console",null],
    ["13-platform.html","13. Gateway as a platform",null],
    ["14-glossary.html","Glossary and quiz",null]
  ];
  var here=location.pathname.split("/").pop()||"index.html";
  var h='<div class="brand">Kill <span>Switch</span></div><div class="sub">Learn the gateway platform</div>';
  var idx=-1;
  pages.forEach(function(p,i){
    if(p[2]) h+='<div class="grp">'+p[2]+'</div>';
    var cur=(p[0]===here); if(cur) idx=i;
    h+='<a href="'+p[0]+'"'+(cur?' class="cur"':'')+'>'+p[1]+'</a>';
  });
  var n=document.getElementById("side"); if(n) n.innerHTML=h;
  var pg=document.getElementById("pager");
  if(pg&&idx>=0){
    var s="";
    if(idx>0) s+='<a href="'+pages[idx-1][0]+'"><small>Previous</small>'+pages[idx-1][1]+'</a>'; else s+='<span style="flex:1"></span>';
    if(idx<pages.length-1) s+='<a class="next" href="'+pages[idx+1][0]+'"><small>Next</small>'+pages[idx+1][1]+'</a>';
    pg.innerHTML=s;
  }
})();
