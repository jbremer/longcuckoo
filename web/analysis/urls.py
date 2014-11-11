# Copyright (C) 2010-2014 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file "docs/LICENSE" for copying permission.

from django.conf.urls import patterns, url

urlpatterns = patterns("",
    url(r"^$", "analysis.views.index"),
    url(r"^(?P<task_id>\d+)/$", "analysis.views.report"),
    url(r"^remove/(?P<task_id>\d+)/$", "analysis.views.remove"),
    url(r"^chunk/(?P<task_id>\d+)/(?P<pid>\d+)/(?P<pagenum>\d+)/$", "analysis.views.chunk"),
    url(r"^filtered/(?P<task_id>\d+)/(?P<pid>\d+)/(?P<category>\w+)/$", "analysis.views.filtered_chunk"),
    url(r"^search/$", "analysis.views.search"),
    url(r"^pending/$", "analysis.views.pending"),
    url(r"^experiment/$", "analysis.views.experiment"),
    url(r"^experiment/(?P<experiment_id>\d+)/$", "analysis.views.experiment"),
    # Support for recurrent analysis
    url(r"^schedule/(?P<task_id>\d+)/$", "analysis.views.schedule"),
    url(r"^unschedule/(?P<task_id>\d+)/$", "analysis.views.unschedule"),
    url(r"^terminate/(?P<task_id>\d+)/$", "analysis.views.terminate"),
    url(r"^start/(?P<task_id>\d+)/$", "analysis.views.start"),
)
