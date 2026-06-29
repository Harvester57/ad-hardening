(function() {
    function initCollapsibleMenu() {
        // Hide duplicate header titles that match the following chapter link
        var headers = document.querySelectorAll('.book-summary ul.summary li.header');
        headers.forEach(function(header) {
            var nextSibling = header.nextElementSibling;
            if (nextSibling && nextSibling.classList.contains('chapter')) {
                var link = nextSibling.querySelector('a');
                if (link) {
                    var headerText = header.textContent.trim().toLowerCase();
                    var linkText = link.textContent.trim().toLowerCase();
                    if (headerText === linkText) {
                        header.style.display = 'none';
                    }
                }
            }
        });

        var chapters = document.querySelectorAll('.book-summary ul.summary li.chapter');
        
        chapters.forEach(function(chapter) {
            var articles = chapter.querySelector('ul.articles');
            if (!articles) return;
            
            // Add has-toggle class to adjust link layout
            chapter.classList.add('has-toggle');
            
            if (chapter.querySelector('.menu-toggle-arrow')) return;
            
            var toggle = document.createElement('span');
            toggle.className = 'menu-toggle-arrow';
            
            chapter.appendChild(toggle);
            
            // Expand the chapter if it or any child is currently active
            var isActive = chapter.classList.contains('active') || 
                           chapter.querySelector('li.chapter.active') !== null;
            
            if (isActive) {
                chapter.classList.add('expanded');
            } else {
                chapter.classList.remove('expanded');
            }
            
            toggle.addEventListener('click', function(e) {
                e.preventDefault();
                e.stopPropagation();
                chapter.classList.toggle('expanded');
            });
        });
    }

    if (typeof gitbook !== 'undefined') {
        gitbook.events.bind('page.change', function() {
            initCollapsibleMenu();
        });
    } else {
        document.addEventListener('DOMContentLoaded', initCollapsibleMenu);
    }
})();
