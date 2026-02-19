(function(){
  const deckOrder = [
    "00_overview_slides.html",
    "01_entry_point_slides.html",
    "02_friendly_file_slides.html",
    "03_static_engine_cascade_slides.html",
    "04_aaggregator_collection_slides.html",
    "05_pe_emulation_slides.html",
    "06_unpacked_content_slides.html",
    "07_container_extraction_slides.html",
    "08_script_deobfuscation_slides.html",
    "09_brute_matching_slides.html",
    "10_lua_scripts_slides.html",
    "11_aaggregator_evaluation_slides.html",
    "12_maps_cloud_lookup_slides.html",
    "13_verdict_resolution_slides.html",
    "14_sigtree_ml_model_slides.html"
  ];

  const currentFile = location.pathname.split("/").pop();
  const currentDeckIndex = deckOrder.indexOf(currentFile);
  if (currentDeckIndex === -1) {
    return;
  }

  const slides = Array.from(document.querySelectorAll(".slide"));
  if (!slides.length) {
    return;
  }

  const toDeckHref = function(index) {
    if (index < 0 || index >= deckOrder.length) {
      return null;
    }
    return deckOrder[index] + "#1";
  };

  const goDeck = function(index) {
    const href = toDeckHref(index);
    if (href) {
      location.href = href;
      return;
    }
    location.href = "../master_slide.html?from=" + currentDeckIndex;
  };

  const goBack = function() {
    if (window.history.length > 1) {
      window.history.back();
      return;
    }
    const fallback = toDeckHref(currentDeckIndex - 1);
    if (fallback) {
      location.href = fallback;
      return;
    }
    location.href = "../master_slide.html?from=" + currentDeckIndex;
  };

  const getCurrentSlideIndex = function() {
    const active = document.querySelector(".slide.active");
    if (!active) {
      return 0;
    }
    const idx = slides.indexOf(active);
    return idx === -1 ? 0 : idx;
  };

  const isInteractiveTarget = function(target) {
    if (!target || !(target instanceof HTMLElement)) {
      return false;
    }
    if (target.closest("#deck-master-nav")) {
      return true;
    }
    const tag = target.tagName;
    return tag === "A" || tag === "BUTTON" || tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT";
  };

  const makeLink = function(text, href, disabled) {
    const a = document.createElement("a");
    a.textContent = text;
    if (!disabled && href) {
      a.href = href;
    } else {
      a.setAttribute("aria-disabled", "true");
      a.tabIndex = -1;
    }
    return a;
  };

  const makeAction = function(text, onClick) {
    const a = document.createElement("a");
    a.textContent = text;
    a.href = "#";
    a.addEventListener("click", function(e) {
      e.preventDefault();
      onClick();
    });
    return a;
  };

  const nav = document.createElement("div");
  nav.id = "deck-master-nav";

  const style = document.createElement("style");
  style.textContent = [
    "#deck-master-nav{position:fixed;top:14px;right:14px;z-index:1000;display:flex;gap:8px;align-items:center;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif}",
    "#deck-master-nav a{padding:6px 10px;border-radius:8px;border:1px solid rgba(255,255,255,0.25);background:rgba(7,10,18,0.78);color:#f0f3ff;text-decoration:none;font-size:12px;line-height:1;backdrop-filter:blur(6px);cursor:pointer}",
    "#deck-master-nav a:hover{border-color:rgba(255,255,255,0.45);background:rgba(7,10,18,0.95)}",
    "#deck-master-nav a[aria-disabled='true']{opacity:0.35;pointer-events:none}",
    "@media(max-width:768px){#deck-master-nav{top:8px;right:8px;gap:6px}#deck-master-nav a{font-size:11px;padding:5px 8px}}"
  ].join("");

  const prevHref = toDeckHref(currentDeckIndex - 1);
  const nextHref = toDeckHref(currentDeckIndex + 1);

  nav.appendChild(makeAction("Back", goBack));
  nav.appendChild(makeLink("Master", "../master_slide.html?from=" + currentDeckIndex, false));
  nav.appendChild(makeLink("Prev Deck", prevHref, !prevHref));
  nav.appendChild(makeLink("Next Deck", nextHref, !nextHref));

  document.head.appendChild(style);
  document.body.appendChild(nav);

  const nextKeys = new Set(["ArrowRight", "PageDown", " ", "Spacebar"]);
  const prevKeys = new Set(["ArrowLeft", "PageUp"]);

  document.addEventListener("keydown", function(e) {
    if (isInteractiveTarget(e.target)) {
      return;
    }

    const idx = getCurrentSlideIndex();

    if (nextKeys.has(e.key) && idx === slides.length - 1) {
      e.preventDefault();
      e.stopImmediatePropagation();
      goDeck(currentDeckIndex + 1);
      return;
    }

    if (prevKeys.has(e.key) && idx === 0) {
      e.preventDefault();
      e.stopImmediatePropagation();
      goDeck(currentDeckIndex - 1);
      return;
    }

    if (e.key === "m" || e.key === "M") {
      e.preventDefault();
      e.stopImmediatePropagation();
      location.href = "../master_slide.html?from=" + currentDeckIndex;
      return;
    }

    if (e.key === "b" || e.key === "B") {
      e.preventDefault();
      e.stopImmediatePropagation();
      goBack();
    }
  }, true);

  const deckRoot = document.getElementById("deck");
  if (deckRoot) {
    deckRoot.addEventListener("click", function(e) {
      if (isInteractiveTarget(e.target)) {
        return;
      }
      const idx = getCurrentSlideIndex();
      if (e.clientX > window.innerWidth * 0.65 && idx === slides.length - 1) {
        e.preventDefault();
        e.stopImmediatePropagation();
        goDeck(currentDeckIndex + 1);
      } else if (e.clientX < window.innerWidth * 0.35 && idx === 0) {
        e.preventDefault();
        e.stopImmediatePropagation();
        goDeck(currentDeckIndex - 1);
      }
    }, true);
  }

  let touchStartX = 0;
  document.addEventListener("touchstart", function(e) {
    const first = e.changedTouches && e.changedTouches[0];
    if (first) {
      touchStartX = first.clientX;
    }
  }, { passive: true, capture: true });

  document.addEventListener("touchend", function(e) {
    const first = e.changedTouches && e.changedTouches[0];
    if (!first) {
      return;
    }

    const dx = first.clientX - touchStartX;
    if (Math.abs(dx) <= 50) {
      return;
    }

    const idx = getCurrentSlideIndex();
    if (dx < 0 && idx === slides.length - 1) {
      e.preventDefault();
      e.stopImmediatePropagation();
      goDeck(currentDeckIndex + 1);
    } else if (dx > 0 && idx === 0) {
      e.preventDefault();
      e.stopImmediatePropagation();
      goDeck(currentDeckIndex - 1);
    }
  }, { passive: false, capture: true });
})();
