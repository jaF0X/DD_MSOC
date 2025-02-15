resource "datadog_dashboard_json" "dashboard_json" {
    dashboard = <<EOF
{
    "title": "SOC Single Pane of Glass",
    "description": "[[suggested_dashboards]]",
    "widgets": [
        {
            "id": 1305627963183676,
            "definition": {
                "title": "Operational Metrics",
                "background_color": "blue",
                "show_title": true,
                "type": "group",
                "layout_type": "ordered",
                "widgets": [
                    {
                        "id": 6425135512137127,
                        "definition": {
                            "title": "Mean Time to Detect (MTTD)",
                            "title_size": "16",
                            "title_align": "left",
                            "time": {
                                "type": "live",
                                "unit": "month",
                                "value": 1
                            },
                            "type": "query_value",
                            "requests": [
                                {
                                    "response_format": "scalar",
                                    "queries": [
                                        {
                                            "data_source": "metrics",
                                            "name": "query1",
                                            "query": "avg:datadog.security.siem_signal.time_to_detect{*}",
                                            "aggregator": "avg"
                                        }
                                    ],
                                    "formulas": [
                                        {
                                            "formula": "query1",
                                            "number_format": {
                                                "unit": {
                                                    "type": "canonical_unit",
                                                    "unit_name": "second"
                                                }
                                            }
                                        }
                                    ]
                                }
                            ],
                            "autoscale": true,
                            "precision": 2
                        },
                        "layout": {
                            "x": 0,
                            "y": 0,
                            "width": 4,
                            "height": 2
                        }
                    },
                    {
                        "id": 1968423607254329,
                        "definition": {
                            "title": "Mean Time to Acknowledge (MTTA)",
                            "title_size": "16",
                            "title_align": "left",
                            "time": {
                                "type": "live",
                                "unit": "month",
                                "value": 1
                            },
                            "type": "query_value",
                            "requests": [
                                {
                                    "response_format": "scalar",
                                    "queries": [
                                        {
                                            "data_source": "metrics",
                                            "name": "query1",
                                            "query": "avg:datadog.security.siem_signal.time_to_acknowledge{*}",
                                            "aggregator": "avg"
                                        }
                                    ],
                                    "formulas": [
                                        {
                                            "formula": "query1",
                                            "number_format": {
                                                "unit": {
                                                    "type": "canonical_unit",
                                                    "unit_name": "second"
                                                }
                                            }
                                        }
                                    ]
                                }
                            ],
                            "autoscale": true,
                            "precision": 2
                        },
                        "layout": {
                            "x": 4,
                            "y": 0,
                            "width": 4,
                            "height": 2
                        }
                    },
                    {
                        "id": 1808369351022375,
                        "definition": {
                            "title": "Mean Time to Resolve (MTTR)",
                            "title_size": "16",
                            "title_align": "left",
                            "time": {
                                "type": "live",
                                "unit": "month",
                                "value": 1
                            },
                            "type": "query_value",
                            "requests": [
                                {
                                    "response_format": "scalar",
                                    "queries": [
                                        {
                                            "data_source": "metrics",
                                            "name": "query1",
                                            "query": "avg:datadog.security.siem_signal.time_to_resolve{*}",
                                            "aggregator": "avg"
                                        }
                                    ],
                                    "formulas": [
                                        {
                                            "formula": "query1",
                                            "number_format": {
                                                "unit": {
                                                    "type": "canonical_unit",
                                                    "unit_name": "second"
                                                }
                                            }
                                        }
                                    ]
                                }
                            ],
                            "autoscale": true,
                            "precision": 2
                        },
                        "layout": {
                            "x": 8,
                            "y": 0,
                            "width": 4,
                            "height": 2
                        }
                    },
                    {
                        "id": 6195844939780915,
                        "definition": {
                            "title": "Change in Mean Time to Detect (MTTD)",
                            "title_size": "16",
                            "title_align": "left",
                            "time": {
                                "type": "live",
                                "unit": "week",
                                "value": 1
                            },
                            "type": "change",
                            "requests": [
                                {
                                    "increase_good": false,
                                    "order_by": "change",
                                    "change_type": "absolute",
                                    "order_dir": "desc",
                                    "response_format": "scalar",
                                    "formulas": [
                                        {
                                            "formula": "week_before(query1)",
                                            "number_format": {
                                                "unit": {
                                                    "type": "canonical_unit",
                                                    "unit_name": "second"
                                                }
                                            }
                                        },
                                        {
                                            "formula": "query1"
                                        }
                                    ],
                                    "queries": [
                                        {
                                            "data_source": "metrics",
                                            "name": "query1",
                                            "query": "avg:datadog.security.siem_signal.time_to_detect{*}",
                                            "aggregator": "avg"
                                        }
                                    ]
                                }
                            ]
                        },
                        "layout": {
                            "x": 0,
                            "y": 2,
                            "width": 4,
                            "height": 2
                        }
                    },
                    {
                        "id": 1535240265342333,
                        "definition": {
                            "title": "Change in Mean Time to Acknowledge (MTTA)",
                            "title_size": "16",
                            "title_align": "left",
                            "time": {
                                "type": "live",
                                "unit": "week",
                                "value": 1
                            },
                            "type": "change",
                            "requests": [
                                {
                                    "increase_good": false,
                                    "order_by": "change",
                                    "change_type": "absolute",
                                    "order_dir": "desc",
                                    "response_format": "scalar",
                                    "formulas": [
                                        {
                                            "formula": "week_before(query1)",
                                            "number_format": {
                                                "unit": {
                                                    "type": "canonical_unit",
                                                    "unit_name": "second"
                                                }
                                            }
                                        },
                                        {
                                            "formula": "query1"
                                        }
                                    ],
                                    "queries": [
                                        {
                                            "data_source": "metrics",
                                            "name": "query1",
                                            "query": "avg:datadog.security.siem_signal.time_to_acknowledge{*}",
                                            "aggregator": "avg"
                                        }
                                    ]
                                }
                            ]
                        },
                        "layout": {
                            "x": 4,
                            "y": 2,
                            "width": 4,
                            "height": 2
                        }
                    },
                    {
                        "id": 2084060974454354,
                        "definition": {
                            "title": "Change in Mean Time to Resolve (MTTR)",
                            "title_size": "16",
                            "title_align": "left",
                            "type": "change",
                            "requests": [
                                {
                                    "increase_good": false,
                                    "order_by": "change",
                                    "change_type": "absolute",
                                    "order_dir": "desc",
                                    "response_format": "scalar",
                                    "formulas": [
                                        {
                                            "formula": "week_before(query1)",
                                            "number_format": {
                                                "unit": {
                                                    "type": "canonical_unit",
                                                    "unit_name": "second"
                                                }
                                            }
                                        },
                                        {
                                            "formula": "query1"
                                        }
                                    ],
                                    "queries": [
                                        {
                                            "data_source": "metrics",
                                            "name": "query1",
                                            "query": "avg:datadog.security.siem_signal.time_to_resolve{*}",
                                            "aggregator": "avg"
                                        }
                                    ]
                                }
                            ]
                        },
                        "layout": {
                            "x": 8,
                            "y": 2,
                            "width": 4,
                            "height": 2
                        }
                    }
                ]
            },
            "layout": {
                "x": 0,
                "y": 0,
                "width": 12,
                "height": 1
            }
        },
        {
            "id": 5000025672753932,
            "definition": {
                "title": "Operations Overview",
                "background_color": "orange",
                "show_title": true,
                "type": "group",
                "layout_type": "ordered",
                "widgets": [
                    {
                        "id": 2686178288344919,
                        "definition": {
                            "title": "Security Signals by Severity",
                            "title_size": "16",
                            "title_align": "left",
                            "show_legend": true,
                            "legend_layout": "auto",
                            "legend_columns": [
                                "avg",
                                "min",
                                "max",
                                "value",
                                "sum"
                            ],
                            "type": "timeseries",
                            "requests": [
                                {
                                    "formulas": [
                                        {
                                            "formula": "query1"
                                        },
                                        {
                                            "formula": "query2"
                                        },
                                        {
                                            "formula": "query3"
                                        },
                                        {
                                            "formula": "query4"
                                        },
                                        {
                                            "formula": "query5"
                                        }
                                    ],
                                    "queries": [
                                        {
                                            "data_source": "security_signals",
                                            "name": "query1",
                                            "indexes": [
                                                "*"
                                            ],
                                            "compute": {
                                                "aggregation": "count"
                                            },
                                            "group_by": [
                                                {
                                                    "facet": "status",
                                                    "limit": 10,
                                                    "sort": {
                                                        "order": "desc",
                                                        "aggregation": "count"
                                                    }
                                                }
                                            ],
                                            "search": {
                                                "query": "status:critical"
                                            }
                                        },
                                        {
                                            "data_source": "security_signals",
                                            "name": "query2",
                                            "indexes": [
                                                "*"
                                            ],
                                            "compute": {
                                                "aggregation": "count"
                                            },
                                            "group_by": [
                                                {
                                                    "facet": "status",
                                                    "limit": 10,
                                                    "sort": {
                                                        "order": "desc",
                                                        "aggregation": "count"
                                                    }
                                                }
                                            ],
                                            "search": {
                                                "query": "status:high"
                                            }
                                        },
                                        {
                                            "data_source": "security_signals",
                                            "name": "query3",
                                            "indexes": [
                                                "*"
                                            ],
                                            "compute": {
                                                "aggregation": "count"
                                            },
                                            "group_by": [
                                                {
                                                    "facet": "status",
                                                    "limit": 10,
                                                    "sort": {
                                                        "order": "desc",
                                                        "aggregation": "count"
                                                    }
                                                }
                                            ],
                                            "search": {
                                                "query": "status:medium"
                                            }
                                        },
                                        {
                                            "data_source": "security_signals",
                                            "name": "query4",
                                            "indexes": [
                                                "*"
                                            ],
                                            "compute": {
                                                "aggregation": "count"
                                            },
                                            "group_by": [
                                                {
                                                    "facet": "status",
                                                    "limit": 10,
                                                    "sort": {
                                                        "order": "desc",
                                                        "aggregation": "count"
                                                    }
                                                }
                                            ],
                                            "search": {
                                                "query": "status:low"
                                            }
                                        },
                                        {
                                            "data_source": "security_signals",
                                            "name": "query5",
                                            "indexes": [
                                                "*"
                                            ],
                                            "compute": {
                                                "aggregation": "count"
                                            },
                                            "group_by": [
                                                {
                                                    "facet": "status",
                                                    "limit": 10,
                                                    "sort": {
                                                        "order": "desc",
                                                        "aggregation": "count"
                                                    }
                                                }
                                            ],
                                            "search": {
                                                "query": "status:info"
                                            }
                                        }
                                    ],
                                    "response_format": "timeseries",
                                    "style": {
                                        "palette": "semantic",
                                        "order_by": "values",
                                        "line_type": "solid",
                                        "line_width": "thick"
                                    },
                                    "display_type": "line"
                                }
                            ]
                        },
                        "layout": {
                            "x": 0,
                            "y": 0,
                            "width": 12,
                            "height": 3
                        }
                    },
                    {
                        "id": 8703101265173129,
                        "definition": {
                            "title": "Critical",
                            "title_size": "16",
                            "title_align": "left",
                            "type": "query_value",
                            "requests": [
                                {
                                    "formulas": [
                                        {
                                            "formula": "query1"
                                        }
                                    ],
                                    "conditional_formats": [
                                        {
                                            "custom_bg_color": "#bc303c",
                                            "comparator": ">",
                                            "palette": "custom_bg",
                                            "value": 0
                                        }
                                    ],
                                    "response_format": "scalar",
                                    "queries": [
                                        {
                                            "search": {
                                                "query": "status:critical"
                                            },
                                            "data_source": "security_signals",
                                            "compute": {
                                                "aggregation": "count"
                                            },
                                            "name": "query1",
                                            "indexes": [
                                                "*"
                                            ],
                                            "group_by": []
                                        }
                                    ]
                                }
                            ],
                            "autoscale": true,
                            "custom_links": [
                                {
                                    "link": "/security?query=status:critical {{$host}}",
                                    "label": "View related Security Signals"
                                }
                            ],
                            "precision": 2
                        },
                        "layout": {
                            "x": 0,
                            "y": 3,
                            "width": 2,
                            "height": 2
                        }
                    },
                    {
                        "id": 3067442921279574,
                        "definition": {
                            "title": "High",
                            "title_size": "16",
                            "title_align": "left",
                            "type": "query_value",
                            "requests": [
                                {
                                    "formulas": [
                                        {
                                            "formula": "query1"
                                        }
                                    ],
                                    "conditional_formats": [
                                        {
                                            "custom_bg_color": "#d33043",
                                            "comparator": ">",
                                            "palette": "custom_bg",
                                            "value": 0
                                        }
                                    ],
                                    "response_format": "scalar",
                                    "queries": [
                                        {
                                            "search": {
                                                "query": "status:high"
                                            },
                                            "data_source": "security_signals",
                                            "compute": {
                                                "aggregation": "count"
                                            },
                                            "name": "query1",
                                            "indexes": [
                                                "*"
                                            ],
                                            "group_by": []
                                        }
                                    ]
                                }
                            ],
                            "autoscale": true,
                            "custom_links": [
                                {
                                    "link": "/security?query=status:high {{$host}}",
                                    "label": "View related Security Signals"
                                }
                            ],
                            "precision": 2
                        },
                        "layout": {
                            "x": 2,
                            "y": 3,
                            "width": 2,
                            "height": 2
                        }
                    },
                    {
                        "id": 8370294943434727,
                        "definition": {
                            "title": "Medium",
                            "title_size": "16",
                            "title_align": "left",
                            "type": "query_value",
                            "requests": [
                                {
                                    "formulas": [
                                        {
                                            "formula": "query1"
                                        }
                                    ],
                                    "conditional_formats": [
                                        {
                                            "custom_bg_color": "#e5a21c",
                                            "comparator": ">",
                                            "palette": "custom_bg",
                                            "value": 0
                                        }
                                    ],
                                    "response_format": "scalar",
                                    "queries": [
                                        {
                                            "search": {
                                                "query": "status:medium"
                                            },
                                            "data_source": "security_signals",
                                            "compute": {
                                                "aggregation": "count"
                                            },
                                            "name": "query1",
                                            "indexes": [
                                                "*"
                                            ],
                                            "group_by": []
                                        }
                                    ]
                                }
                            ],
                            "autoscale": true,
                            "custom_links": [
                                {
                                    "link": "/security?query=status:medium {{$host}}",
                                    "label": "View related Security Signals"
                                }
                            ],
                            "precision": 2
                        },
                        "layout": {
                            "x": 4,
                            "y": 3,
                            "width": 2,
                            "height": 2
                        }
                    },
                    {
                        "id": 4547572672713355,
                        "definition": {
                            "title": "Low",
                            "title_size": "16",
                            "title_align": "left",
                            "type": "query_value",
                            "requests": [
                                {
                                    "formulas": [
                                        {
                                            "formula": "query1"
                                        }
                                    ],
                                    "conditional_formats": [
                                        {
                                            "custom_bg_color": "#ffb52b",
                                            "comparator": ">",
                                            "palette": "custom_bg",
                                            "value": 0
                                        }
                                    ],
                                    "response_format": "scalar",
                                    "queries": [
                                        {
                                            "search": {
                                                "query": "status:low"
                                            },
                                            "data_source": "security_signals",
                                            "compute": {
                                                "aggregation": "count"
                                            },
                                            "name": "query1",
                                            "indexes": [
                                                "*"
                                            ],
                                            "group_by": []
                                        }
                                    ]
                                }
                            ],
                            "autoscale": true,
                            "custom_links": [
                                {
                                    "link": "/security?query=status:low {{$host}}",
                                    "label": "View related Security Signals"
                                }
                            ],
                            "precision": 2
                        },
                        "layout": {
                            "x": 6,
                            "y": 3,
                            "width": 2,
                            "height": 2
                        }
                    },
                    {
                        "id": 193366105517987,
                        "definition": {
                            "title": "Info",
                            "title_size": "16",
                            "title_align": "left",
                            "type": "query_value",
                            "requests": [
                                {
                                    "formulas": [
                                        {
                                            "formula": "query1"
                                        }
                                    ],
                                    "conditional_formats": [
                                        {
                                            "custom_bg_color": "#84c1e0",
                                            "comparator": ">",
                                            "palette": "custom_bg",
                                            "value": 0
                                        }
                                    ],
                                    "response_format": "scalar",
                                    "queries": [
                                        {
                                            "search": {
                                                "query": "status:info"
                                            },
                                            "data_source": "security_signals",
                                            "compute": {
                                                "aggregation": "count"
                                            },
                                            "name": "query1",
                                            "indexes": [
                                                "*"
                                            ],
                                            "group_by": []
                                        }
                                    ]
                                }
                            ],
                            "autoscale": true,
                            "custom_links": [
                                {
                                    "link": "/security?query=status:info {{$host}}",
                                    "label": "View related Security Signals"
                                }
                            ],
                            "precision": 2
                        },
                        "layout": {
                            "x": 8,
                            "y": 3,
                            "width": 2,
                            "height": 2
                        }
                    },
                    {
                        "id": 2766554073089557,
                        "definition": {
                            "title": "Top Log Sources",
                            "title_size": "16",
                            "title_align": "left",
                            "type": "toplist",
                            "requests": [
                                {
                                    "response_format": "scalar",
                                    "queries": [
                                        {
                                            "search": {
                                                "query": ""
                                            },
                                            "data_source": "logs",
                                            "compute": {
                                                "aggregation": "count"
                                            },
                                            "name": "query1",
                                            "indexes": [
                                                "*"
                                            ],
                                            "group_by": [
                                                {
                                                    "facet": "source",
                                                    "sort": {
                                                        "aggregation": "count",
                                                        "order": "desc"
                                                    },
                                                    "limit": 10
                                                }
                                            ]
                                        }
                                    ],
                                    "formulas": [
                                        {
                                            "formula": "query1"
                                        }
                                    ],
                                    "sort": {
                                        "count": 10,
                                        "order_by": [
                                            {
                                                "type": "formula",
                                                "index": 0,
                                                "order": "desc"
                                            }
                                        ]
                                    }
                                }
                            ]
                        },
                        "layout": {
                            "x": 0,
                            "y": 5,
                            "width": 6,
                            "height": 3
                        }
                    },
                    {
                        "id": 6507993225128726,
                        "definition": {
                            "title": "Top Sources of Security Signals",
                            "type": "toplist",
                            "requests": [
                                {
                                    "conditional_formats": [
                                        {
                                            "comparator": ">",
                                            "palette": "white_on_red",
                                            "value": 0
                                        }
                                    ],
                                    "response_format": "scalar",
                                    "queries": [
                                        {
                                            "data_source": "security_signals",
                                            "name": "query1",
                                            "indexes": [
                                                "*"
                                            ],
                                            "compute": {
                                                "aggregation": "count"
                                            },
                                            "group_by": [
                                                {
                                                    "facet": "source",
                                                    "limit": 10,
                                                    "sort": {
                                                        "order": "desc",
                                                        "aggregation": "count"
                                                    }
                                                }
                                            ],
                                            "search": {
                                                "query": "@workflow.rule.type:(\"Log Detection\" OR \"Signal Correlation\")"
                                            }
                                        }
                                    ],
                                    "formulas": [
                                        {
                                            "formula": "query1"
                                        }
                                    ],
                                    "sort": {
                                        "count": 10,
                                        "order_by": [
                                            {
                                                "type": "formula",
                                                "index": 0,
                                                "order": "desc"
                                            }
                                        ]
                                    }
                                }
                            ],
                            "custom_links": [
                                {
                                    "link": "/security?query=@workflow.rule.type:(\"Log Detection\" OR \"Signal Correlation\") {{source}}&start={{timestamp_start}}&end={{timestamp_end}}&paused=true&=",
                                    "label": "View related Security Signals"
                                }
                            ],
                            "style": {}
                        },
                        "layout": {
                            "x": 6,
                            "y": 5,
                            "width": 6,
                            "height": 3
                        }
                    },
                    {
                        "id": 2528961992548146,
                        "definition": {
                            "title": "Top 10 Hosts by Security Signals (1 month)",
                            "title_size": "16",
                            "title_align": "left",
                            "type": "toplist",
                            "requests": [
                                {
                                    "queries": [
                                        {
                                            "data_source": "security_signals",
                                            "name": "query1",
                                            "indexes": [
                                                "*"
                                            ],
                                            "compute": {
                                                "aggregation": "count"
                                            },
                                            "group_by": [
                                                {
                                                    "facet": "host",
                                                    "limit": 25,
                                                    "sort": {
                                                        "order": "desc",
                                                        "aggregation": "count"
                                                    }
                                                }
                                            ],
                                            "search": {
                                                "query": ""
                                            }
                                        }
                                    ],
                                    "response_format": "scalar",
                                    "formulas": [
                                        {
                                            "formula": "query1"
                                        }
                                    ],
                                    "sort": {
                                        "count": 10,
                                        "order_by": [
                                            {
                                                "type": "formula",
                                                "index": 0,
                                                "order": "desc"
                                            }
                                        ]
                                    }
                                }
                            ],
                            "style": {
                                "display": {
                                    "type": "stacked",
                                    "legend": "automatic"
                                }
                            }
                        },
                        "layout": {
                            "x": 0,
                            "y": 8,
                            "width": 6,
                            "height": 3
                        }
                    },
                    {
                        "id": 8153731685459533,
                        "definition": {
                            "title": "Top Security Signals",
                            "title_size": "16",
                            "title_align": "left",
                            "type": "toplist",
                            "requests": [
                                {
                                    "response_format": "scalar",
                                    "queries": [
                                        {
                                            "data_source": "security_signals",
                                            "name": "query1",
                                            "indexes": [
                                                "*"
                                            ],
                                            "compute": {
                                                "aggregation": "count"
                                            },
                                            "group_by": [
                                                {
                                                    "facet": "@workflow.rule.name",
                                                    "limit": 10,
                                                    "sort": {
                                                        "order": "desc",
                                                        "aggregation": "count"
                                                    }
                                                }
                                            ],
                                            "search": {
                                                "query": ""
                                            }
                                        }
                                    ],
                                    "formulas": [
                                        {
                                            "formula": "query1"
                                        }
                                    ],
                                    "sort": {
                                        "count": 25,
                                        "order_by": [
                                            {
                                                "type": "formula",
                                                "index": 0,
                                                "order": "desc"
                                            }
                                        ]
                                    }
                                }
                            ],
                            "custom_links": [
                                {
                                    "link": "/security?query=@workflow.rule.type%3A(%22Log%20Detection%22%20OR%20%22Signal%20Correlation%22)%20{{@workflow.rule.name}}%20{{$network.client.ip}}%20{{$source}}%20{{$service}}%20{{$env}}&start={{timestamp_start}}&end={{timestamp_end}}&paused=true",
                                    "label": "View related Security Signals"
                                }
                            ],
                            "style": {}
                        },
                        "layout": {
                            "x": 6,
                            "y": 8,
                            "width": 6,
                            "height": 3
                        }
                    }
                ]
            },
            "layout": {
                "x": 0,
                "y": 1,
                "width": 12,
                "height": 1
            }
        },
        {
            "id": 1584051522824260,
            "definition": {
                "title": "Event Status Tracking",
                "background_color": "purple",
                "show_title": true,
                "type": "group",
                "layout_type": "ordered",
                "widgets": [
                    {
                        "id": 4837160436352544,
                        "definition": {
                            "title": "Case Status by Priority",
                            "title_size": "16",
                            "title_align": "left",
                            "show_legend": true,
                            "legend_layout": "horizontal",
                            "legend_columns": [
                                "avg",
                                "min",
                                "max",
                                "value",
                                "sum"
                            ],
                            "type": "timeseries",
                            "requests": [
                                {
                                    "formulas": [
                                        {
                                            "formula": "query1"
                                        },
                                        {
                                            "formula": "query2"
                                        },
                                        {
                                            "formula": "query3"
                                        },
                                        {
                                            "formula": "query4"
                                        },
                                        {
                                            "formula": "query5"
                                        }
                                    ],
                                    "queries": [
                                        {
                                            "name": "query1",
                                            "data_source": "cases",
                                            "query_filter": "priority:P1",
                                            "compute": {
                                                "aggregation": "count"
                                            },
                                            "group_by": [
                                                {
                                                    "field": "status"
                                                }
                                            ],
                                            "sort": "desc",
                                            "limit": 10
                                        },
                                        {
                                            "name": "query2",
                                            "data_source": "cases",
                                            "query_filter": "priority:P2",
                                            "compute": {
                                                "aggregation": "count"
                                            },
                                            "group_by": [
                                                {
                                                    "field": "status"
                                                }
                                            ],
                                            "sort": "desc",
                                            "limit": 10
                                        },
                                        {
                                            "name": "query3",
                                            "data_source": "cases",
                                            "query_filter": "priority:P3",
                                            "compute": {
                                                "aggregation": "count"
                                            },
                                            "group_by": [
                                                {
                                                    "field": "status"
                                                }
                                            ],
                                            "sort": "desc",
                                            "limit": 10
                                        },
                                        {
                                            "name": "query4",
                                            "data_source": "cases",
                                            "query_filter": "priority:P4",
                                            "compute": {
                                                "aggregation": "count"
                                            },
                                            "group_by": [
                                                {
                                                    "field": "status"
                                                }
                                            ],
                                            "sort": "desc",
                                            "limit": 10
                                        },
                                        {
                                            "name": "query5",
                                            "data_source": "cases",
                                            "query_filter": "priority:P5",
                                            "compute": {
                                                "aggregation": "count"
                                            },
                                            "group_by": [
                                                {
                                                    "field": "status"
                                                }
                                            ],
                                            "sort": "desc",
                                            "limit": 10
                                        }
                                    ],
                                    "response_format": "timeseries",
                                    "style": {
                                        "palette": "semantic",
                                        "line_type": "solid",
                                        "line_width": "normal"
                                    },
                                    "display_type": "line"
                                }
                            ],
                            "custom_links": [
                                {
                                    "link": "/security?query=@workflow.rule.type:(\"Log Detection\" OR \"Signal Correlation\") {{status}}&start={{timestamp_start}}&end={{timestamp_end}}&paused=true",
                                    "label": "View Security Signals"
                                }
                            ]
                        },
                        "layout": {
                            "x": 0,
                            "y": 0,
                            "width": 12,
                            "height": 3
                        }
                    },
                    {
                        "id": 6814293533420340,
                        "definition": {
                            "title": "SOC - Tier 1 Case Load",
                            "title_size": "16",
                            "title_align": "left",
                            "type": "query_table",
                            "requests": [
                                {
                                    "queries": [
                                        {
                                            "name": "query1",
                                            "data_source": "cases",
                                            "query_filter": "  project:ef935398-95d3-4031-bb2e-2d1491c21c2e ",
                                            "compute": {
                                                "aggregation": "avg"
                                            },
                                            "group_by": [
                                                {
                                                    "field": "status"
                                                }
                                            ],
                                            "sort": "desc",
                                            "limit": 10
                                        }
                                    ],
                                    "response_format": "scalar",
                                    "sort": {
                                        "count": 10,
                                        "order_by": [
                                            {
                                                "type": "formula",
                                                "index": 0,
                                                "order": "desc"
                                            }
                                        ]
                                    },
                                    "formulas": [
                                        {
                                            "formula": "query1"
                                        }
                                    ]
                                }
                            ],
                            "has_search_bar": "never"
                        },
                        "layout": {
                            "x": 0,
                            "y": 3,
                            "width": 3,
                            "height": 2
                        }
                    },
                    {
                        "id": 595311562680010,
                        "definition": {
                            "title": "SOC - Tier 2 Case Load",
                            "title_size": "16",
                            "title_align": "left",
                            "type": "query_table",
                            "requests": [
                                {
                                    "queries": [
                                        {
                                            "name": "query1",
                                            "data_source": "cases",
                                            "query_filter": "  project:dd86fbb5-85f5-4cde-ac2e-8b402a82be4c ",
                                            "compute": {
                                                "aggregation": "avg"
                                            },
                                            "group_by": [
                                                {
                                                    "field": "status"
                                                }
                                            ],
                                            "sort": "desc",
                                            "limit": 10
                                        }
                                    ],
                                    "response_format": "scalar",
                                    "sort": {
                                        "count": 10,
                                        "order_by": [
                                            {
                                                "type": "formula",
                                                "index": 0,
                                                "order": "desc"
                                            }
                                        ]
                                    },
                                    "formulas": [
                                        {
                                            "formula": "query1",
                                            "cell_display_mode": "number"
                                        }
                                    ]
                                }
                            ],
                            "has_search_bar": "auto"
                        },
                        "layout": {
                            "x": 3,
                            "y": 3,
                            "width": 3,
                            "height": 2
                        }
                    },
                    {
                        "id": 1503466034548359,
                        "definition": {
                            "title": "SOC - Threat Hunters Case Load",
                            "title_size": "16",
                            "title_align": "left",
                            "type": "query_table",
                            "requests": [
                                {
                                    "queries": [
                                        {
                                            "name": "query1",
                                            "data_source": "cases",
                                            "query_filter": "project:96a2b507-1111-4887-8fac-465767c9e08b",
                                            "compute": {
                                                "aggregation": "avg"
                                            },
                                            "group_by": [
                                                {
                                                    "field": "status"
                                                }
                                            ]
                                        }
                                    ],
                                    "response_format": "scalar",
                                    "sort": {
                                        "count": 500,
                                        "order_by": [
                                            {
                                                "type": "formula",
                                                "index": 0,
                                                "order": "desc"
                                            }
                                        ]
                                    },
                                    "formulas": [
                                        {
                                            "formula": "query1"
                                        }
                                    ]
                                }
                            ],
                            "has_search_bar": "auto"
                        },
                        "layout": {
                            "x": 6,
                            "y": 3,
                            "width": 4,
                            "height": 2
                        }
                    }
                ]
            },
            "layout": {
                "x": 0,
                "y": 2,
                "width": 12,
                "height": 1
            }
        },
        {
            "id": 6571520210056613,
            "definition": {
                "title": "Endpoint Monitoring",
                "background_color": "gray",
                "show_title": true,
                "type": "group",
                "layout_type": "ordered",
                "widgets": [
                    {
                        "id": 132350446068263,
                        "definition": {
                            "title": "Amount of free and used disk space per device",
                            "type": "query_table",
                            "requests": [
                                {
                                    "response_format": "scalar",
                                    "queries": [
                                        {
                                            "data_source": "metrics",
                                            "name": "query1",
                                            "query": "avg:system.disk.free{*} by {host}",
                                            "aggregator": "last"
                                        },
                                        {
                                            "data_source": "metrics",
                                            "name": "query2",
                                            "query": "avg:system.disk.used{*} by {host}",
                                            "aggregator": "last"
                                        }
                                    ],
                                    "sort": {
                                        "count": 50,
                                        "order_by": [
                                            {
                                                "type": "formula",
                                                "index": 1,
                                                "order": "desc"
                                            }
                                        ]
                                    },
                                    "formulas": [
                                        {
                                            "alias": "Free disk space",
                                            "formula": "query1"
                                        },
                                        {
                                            "alias": "Used disk space",
                                            "formula": "query2"
                                        }
                                    ]
                                }
                            ]
                        },
                        "layout": {
                            "x": 0,
                            "y": 0,
                            "width": 6,
                            "height": 3
                        }
                    },
                    {
                        "id": 6921992206877568,
                        "definition": {
                            "title": "CPU usage breakdown (%)",
                            "show_legend": false,
                            "legend_layout": "auto",
                            "legend_columns": [
                                "avg",
                                "min",
                                "max",
                                "value",
                                "sum"
                            ],
                            "time": {
                                "type": "live",
                                "unit": "week",
                                "value": 1
                            },
                            "type": "timeseries",
                            "requests": [
                                {
                                    "formulas": [
                                        {
                                            "alias": "% time the CPU spent in an idle state",
                                            "formula": "query1"
                                        },
                                        {
                                            "alias": "% time the CPU spent running the kernel",
                                            "formula": "query2"
                                        },
                                        {
                                            "alias": "% time the CPU spent waiting for IO operations to complete",
                                            "formula": "query3"
                                        },
                                        {
                                            "alias": "% time the CPU spent running user space processes",
                                            "formula": "query4"
                                        },
                                        {
                                            "alias": "% time the virtual CPU spent waiting for the hypervisor to service another virtual CPU",
                                            "formula": "query5"
                                        },
                                        {
                                            "alias": "% time the CPU spent running the virtual processor",
                                            "formula": "query6"
                                        }
                                    ],
                                    "queries": [
                                        {
                                            "query": "avg:system.cpu.idle{*} by {host}",
                                            "data_source": "metrics",
                                            "name": "query1"
                                        },
                                        {
                                            "query": "avg:system.cpu.system{*} by {host}",
                                            "data_source": "metrics",
                                            "name": "query2"
                                        },
                                        {
                                            "query": "avg:system.cpu.iowait{*} by {host}",
                                            "data_source": "metrics",
                                            "name": "query3"
                                        },
                                        {
                                            "query": "avg:system.cpu.user{*} by {host}",
                                            "data_source": "metrics",
                                            "name": "query4"
                                        },
                                        {
                                            "query": "avg:system.cpu.stolen{*} by {host}",
                                            "data_source": "metrics",
                                            "name": "query5"
                                        },
                                        {
                                            "query": "avg:system.cpu.guest{*} by {host}",
                                            "data_source": "metrics",
                                            "name": "query6"
                                        }
                                    ],
                                    "response_format": "timeseries",
                                    "style": {
                                        "palette": "cool",
                                        "line_type": "solid",
                                        "line_width": "normal"
                                    },
                                    "display_type": "line"
                                }
                            ],
                            "yaxis": {
                                "include_zero": true,
                                "scale": "linear",
                                "label": "",
                                "min": "auto",
                                "max": "auto"
                            }
                        },
                        "layout": {
                            "x": 6,
                            "y": 0,
                            "width": 6,
                            "height": 3
                        }
                    },
                    {
                        "id": 8732262761860289,
                        "definition": {
                            "title": "Current Agent NTP offset",
                            "show_legend": false,
                            "legend_layout": "auto",
                            "legend_columns": [
                                "avg",
                                "min",
                                "max",
                                "value",
                                "sum"
                            ],
                            "type": "timeseries",
                            "requests": [
                                {
                                    "formulas": [
                                        {
                                            "alias": "Agent NTP offset",
                                            "formula": "query1"
                                        }
                                    ],
                                    "response_format": "timeseries",
                                    "queries": [
                                        {
                                            "query": "avg:ntp.offset{*}",
                                            "data_source": "metrics",
                                            "name": "query1"
                                        }
                                    ],
                                    "style": {
                                        "palette": "dog_classic",
                                        "line_type": "solid",
                                        "line_width": "normal"
                                    },
                                    "display_type": "line"
                                }
                            ],
                            "yaxis": {
                                "include_zero": true,
                                "scale": "linear",
                                "label": "",
                                "min": "auto",
                                "max": "auto"
                            },
                            "markers": [
                                {
                                    "label": " Offset +1s ",
                                    "value": "0 < y < 1",
                                    "display_type": "ok dashed"
                                },
                                {
                                    "value": "1 < y < 3",
                                    "display_type": "warning dashed"
                                },
                                {
                                    "label": " Offset +3s ",
                                    "value": "y > 3",
                                    "display_type": "error dashed"
                                },
                                {
                                    "label": " Offset -1s ",
                                    "value": "-1 < y < 0",
                                    "display_type": "ok dashed"
                                },
                                {
                                    "value": "-3 < y < -1",
                                    "display_type": "warning dashed"
                                },
                                {
                                    "label": " Offset -3s ",
                                    "value": "y < -3",
                                    "display_type": "error dashed"
                                }
                            ]
                        },
                        "layout": {
                            "x": 0,
                            "y": 3,
                            "width": 6,
                            "height": 3
                        }
                    },
                    {
                        "id": 7896134077075428,
                        "definition": {
                            "title": "Memory Breakdown by Host",
                            "show_legend": false,
                            "legend_layout": "auto",
                            "legend_columns": [
                                "avg",
                                "min",
                                "max",
                                "value",
                                "sum"
                            ],
                            "time": {
                                "type": "live",
                                "unit": "week",
                                "value": 1
                            },
                            "type": "timeseries",
                            "requests": [
                                {
                                    "on_right_yaxis": false,
                                    "formulas": [
                                        {
                                            "alias": "RAM total",
                                            "formula": "query2"
                                        }
                                    ],
                                    "queries": [
                                        {
                                            "query": "sum:system.mem.total{*} by {host}",
                                            "data_source": "metrics",
                                            "name": "query2"
                                        }
                                    ],
                                    "response_format": "timeseries",
                                    "style": {
                                        "palette": "cool",
                                        "line_type": "solid",
                                        "line_width": "normal"
                                    },
                                    "display_type": "line"
                                },
                                {
                                    "on_right_yaxis": false,
                                    "formulas": [
                                        {
                                            "alias": "RAM used",
                                            "formula": "query0"
                                        }
                                    ],
                                    "queries": [
                                        {
                                            "query": "sum:system.mem.used{*} by {host}",
                                            "data_source": "metrics",
                                            "name": "query0"
                                        }
                                    ],
                                    "response_format": "timeseries",
                                    "style": {
                                        "palette": "purple",
                                        "line_type": "solid",
                                        "line_width": "normal"
                                    },
                                    "display_type": "line"
                                }
                            ],
                            "yaxis": {
                                "include_zero": true,
                                "scale": "linear",
                                "label": "",
                                "min": "auto",
                                "max": "auto"
                            },
                            "markers": []
                        },
                        "layout": {
                            "x": 6,
                            "y": 3,
                            "width": 6,
                            "height": 3
                        }
                    }
                ]
            },
            "layout": {
                "x": 0,
                "y": 3,
                "width": 12,
                "height": 1
            }
        },
        {
            "id": 3092619691897038,
            "definition": {
                "title": "Threat Hunting",
                "background_color": "blue",
                "show_title": true,
                "type": "group",
                "layout_type": "ordered",
                "widgets": [
                    {
                        "id": 2963474096679222,
                        "definition": {
                            "title": "Rare Security Signals",
                            "title_size": "16",
                            "title_align": "left",
                            "type": "toplist",
                            "requests": [
                                {
                                    "response_format": "scalar",
                                    "queries": [
                                        {
                                            "data_source": "security_signals",
                                            "name": "query1",
                                            "indexes": [
                                                "*"
                                            ],
                                            "compute": {
                                                "aggregation": "count"
                                            },
                                            "group_by": [
                                                {
                                                    "facet": "@workflow.rule.name",
                                                    "limit": 10,
                                                    "sort": {
                                                        "order": "asc",
                                                        "aggregation": "count"
                                                    }
                                                }
                                            ],
                                            "search": {
                                                "query": ""
                                            }
                                        }
                                    ],
                                    "conditional_formats": [
                                        {
                                            "comparator": ">",
                                            "value": 0,
                                            "palette": "white_on_red"
                                        }
                                    ],
                                    "formulas": [
                                        {
                                            "formula": "query1"
                                        }
                                    ],
                                    "sort": {
                                        "count": 25,
                                        "order_by": [
                                            {
                                                "type": "formula",
                                                "index": 0,
                                                "order": "asc"
                                            }
                                        ]
                                    }
                                }
                            ],
                            "custom_links": [
                                {
                                    "link": "/security?query=@workflow.rule.type%3A(%22Log%20Detection%22%20OR%20%22Signal%20Correlation%22)%20{{@workflow.rule.name}}%20{{$network.client.ip}}%20{{$source}}%20{{$service}}%20{{$env}}&start={{timestamp_start}}&end={{timestamp_end}}&paused=true",
                                    "label": "View related Security Signals"
                                }
                            ],
                            "style": {}
                        },
                        "layout": {
                            "x": 0,
                            "y": 0,
                            "width": 6,
                            "height": 2
                        }
                    },
                    {
                        "id": 3742167600884837,
                        "definition": {
                            "title": "Rare Events Not Generating Security Signals",
                            "title_size": "16",
                            "title_align": "left",
                            "type": "toplist",
                            "requests": [
                                {
                                    "response_format": "scalar",
                                    "queries": [
                                        {
                                            "search": {
                                                "query": ""
                                            },
                                            "data_source": "logs",
                                            "compute": {
                                                "aggregation": "count"
                                            },
                                            "name": "query1",
                                            "indexes": [
                                                "*"
                                            ],
                                            "group_by": [
                                                {
                                                    "facet": "@evt.name",
                                                    "sort": {
                                                        "aggregation": "count",
                                                        "order": "asc"
                                                    },
                                                    "limit": 10
                                                }
                                            ]
                                        }
                                    ],
                                    "formulas": [
                                        {
                                            "formula": "query1"
                                        }
                                    ],
                                    "sort": {
                                        "count": 10,
                                        "order_by": [
                                            {
                                                "type": "formula",
                                                "index": 0,
                                                "order": "asc"
                                            }
                                        ]
                                    }
                                }
                            ],
                            "custom_links": [
                                {
                                    "link": "/security?query=@workflow.rule.type%3A(%22Log%20Detection%22%20OR%20%22Signal%20Correlation%22)%20{{$network.client.ip}}%20{{@evt.name}}%20{{$source}}%20{{$service}}%20{{$env}}&start={{timestamp_start}}&end={{timestamp_end}}&paused=true",
                                    "label": "View related Security Signals"
                                }
                            ]
                        },
                        "layout": {
                            "x": 6,
                            "y": 0,
                            "width": 6,
                            "height": 2
                        }
                    },
                    {
                        "id": 1851955708755984,
                        "definition": {
                            "title": "Rare Source IP Addresses",
                            "title_size": "16",
                            "title_align": "left",
                            "type": "toplist",
                            "requests": [
                                {
                                    "queries": [
                                        {
                                            "name": "query1",
                                            "data_source": "logs",
                                            "search": {
                                                "query": "@network.ip.attributes.ip:* -@network.ip.attributes.ip:((fe80*) OR (\\:\\:*) OR (127.*) OR (172.31.*))"
                                            },
                                            "indexes": [
                                                "*"
                                            ],
                                            "group_by": [
                                                {
                                                    "facet": "@network.ip.attributes.ip",
                                                    "limit": 10,
                                                    "sort": {
                                                        "aggregation": "count",
                                                        "order": "asc",
                                                        "metric": "count"
                                                    },
                                                    "should_exclude_missing": true
                                                }
                                            ],
                                            "compute": {
                                                "aggregation": "count"
                                            },
                                            "storage": "hot"
                                        }
                                    ],
                                    "response_format": "scalar",
                                    "formulas": [
                                        {
                                            "formula": "query1"
                                        }
                                    ],
                                    "sort": {
                                        "count": 10,
                                        "order_by": [
                                            {
                                                "type": "formula",
                                                "index": 0,
                                                "order": "asc"
                                            }
                                        ]
                                    }
                                }
                            ],
                            "style": {
                                "display": {
                                    "type": "stacked",
                                    "legend": "automatic"
                                }
                            }
                        },
                        "layout": {
                            "x": 0,
                            "y": 2,
                            "width": 6,
                            "height": 2
                        }
                    },
                    {
                        "id": 1820762073147332,
                        "definition": {
                            "title": "Rare Destination IP Addresses",
                            "title_size": "16",
                            "title_align": "left",
                            "type": "toplist",
                            "requests": [
                                {
                                    "queries": [
                                        {
                                            "name": "query1",
                                            "data_source": "logs",
                                            "search": {
                                                "query": "@network.server.ip"
                                            },
                                            "indexes": [
                                                "*"
                                            ],
                                            "group_by": [],
                                            "compute": {
                                                "aggregation": "count"
                                            },
                                            "storage": "hot"
                                        }
                                    ],
                                    "response_format": "scalar",
                                    "formulas": [
                                        {
                                            "formula": "query1"
                                        }
                                    ],
                                    "sort": {
                                        "count": 10,
                                        "order_by": [
                                            {
                                                "type": "formula",
                                                "index": 0,
                                                "order": "asc"
                                            }
                                        ]
                                    }
                                }
                            ],
                            "style": {
                                "display": {
                                    "type": "stacked",
                                    "legend": "automatic"
                                }
                            }
                        },
                        "layout": {
                            "x": 6,
                            "y": 2,
                            "width": 6,
                            "height": 2
                        }
                    },
                    {
                        "id": 7702290174532830,
                        "definition": {
                            "title": "Rare Autonomous System Numbers",
                            "title_size": "16",
                            "title_align": "left",
                            "type": "toplist",
                            "requests": [
                                {
                                    "queries": [
                                        {
                                            "name": "query1",
                                            "data_source": "logs",
                                            "search": {
                                                "query": "@network.client.geoip.as.number:*"
                                            },
                                            "indexes": [
                                                "*"
                                            ],
                                            "group_by": [
                                                {
                                                    "facet": "@network.client.geoip.as.name",
                                                    "limit": 10,
                                                    "sort": {
                                                        "aggregation": "count",
                                                        "order": "asc",
                                                        "metric": "count"
                                                    },
                                                    "should_exclude_missing": true
                                                }
                                            ],
                                            "compute": {
                                                "aggregation": "count"
                                            },
                                            "storage": "hot"
                                        }
                                    ],
                                    "response_format": "scalar",
                                    "formulas": [
                                        {
                                            "formula": "query1"
                                        }
                                    ],
                                    "sort": {
                                        "count": 10,
                                        "order_by": [
                                            {
                                                "type": "formula",
                                                "index": 0,
                                                "order": "asc"
                                            }
                                        ]
                                    }
                                }
                            ],
                            "style": {
                                "display": {
                                    "type": "stacked",
                                    "legend": "automatic"
                                }
                            }
                        },
                        "layout": {
                            "x": 0,
                            "y": 4,
                            "width": 6,
                            "height": 2
                        }
                    },
                    {
                        "id": 6265888204591266,
                        "definition": {
                            "title": "Rare User Agents",
                            "title_size": "16",
                            "title_align": "left",
                            "type": "toplist",
                            "requests": [
                                {
                                    "response_format": "scalar",
                                    "queries": [
                                        {
                                            "name": "query1",
                                            "data_source": "logs",
                                            "search": {
                                                "query": ""
                                            },
                                            "indexes": [
                                                "*"
                                            ],
                                            "group_by": [
                                                {
                                                    "facet": "@http.useragent",
                                                    "limit": 25,
                                                    "sort": {
                                                        "aggregation": "count",
                                                        "order": "asc",
                                                        "metric": "count"
                                                    },
                                                    "should_exclude_missing": true
                                                }
                                            ],
                                            "compute": {
                                                "aggregation": "count"
                                            },
                                            "storage": "hot"
                                        }
                                    ],
                                    "formulas": [
                                        {
                                            "formula": "query1"
                                        }
                                    ],
                                    "sort": {
                                        "count": 25,
                                        "order_by": [
                                            {
                                                "type": "formula",
                                                "index": 0,
                                                "order": "asc"
                                            }
                                        ]
                                    }
                                }
                            ],
                            "custom_links": [
                                {
                                    "label": "View related Security Signals",
                                    "link": "/security?query=@workflow.rule.type%3A(%22Log%20Detection%22%20OR%20%22Signal%20Correlation%22)%20{{@http.useragent}}%20{{$network.client.ip}}%20{{$source}}%20{{$service}}%20{{$env}}&start={{timestamp_start}}&end={{timestamp_end}}&paused=true"
                                }
                            ],
                            "style": {}
                        },
                        "layout": {
                            "x": 6,
                            "y": 4,
                            "width": 6,
                            "height": 2
                        }
                    },
                    {
                        "id": 8242762232704566,
                        "definition": {
                            "title": "Rare URLs",
                            "title_size": "16",
                            "title_align": "left",
                            "type": "toplist",
                            "requests": [
                                {
                                    "response_format": "scalar",
                                    "queries": [
                                        {
                                            "data_source": "security_signals",
                                            "name": "query1",
                                            "indexes": [
                                                "*"
                                            ],
                                            "compute": {
                                                "aggregation": "count"
                                            },
                                            "group_by": [
                                                {
                                                    "facet": "@http.url_details.path",
                                                    "limit": 25,
                                                    "sort": {
                                                        "order": "asc",
                                                        "aggregation": "count"
                                                    }
                                                }
                                            ],
                                            "search": {
                                                "query": ""
                                            }
                                        }
                                    ],
                                    "formulas": [
                                        {
                                            "formula": "query1"
                                        }
                                    ],
                                    "sort": {
                                        "count": 25,
                                        "order_by": [
                                            {
                                                "type": "formula",
                                                "index": 0,
                                                "order": "asc"
                                            }
                                        ]
                                    }
                                }
                            ],
                            "custom_links": [
                                {
                                    "link": "/security?query=@workflow.rule.type%3A(%22Log%20Detection%22%20OR%20%22Signal%20Correlation%22)%20{{@http.useragent}}%20{{$network.client.ip}}%20{{$source}}%20{{$service}}%20{{$env}}&start={{timestamp_start}}&end={{timestamp_end}}&paused=true",
                                    "label": "View related Security Signals"
                                }
                            ],
                            "style": {}
                        },
                        "layout": {
                            "x": 0,
                            "y": 6,
                            "width": 6,
                            "height": 2
                        }
                    }
                ]
            },
            "layout": {
                "x": 0,
                "y": 4,
                "width": 12,
                "height": 1
            }
        },
        {
            "id": 3993578100842777,
            "definition": {
                "title": "Network Monitoring",
                "background_color": "pink",
                "show_title": true,
                "type": "group",
                "layout_type": "ordered",
                "widgets": [
                    {
                        "id": 1027855441446390,
                        "definition": {
                            "title": "Source IP Addresses by Country",
                            "title_size": "16",
                            "title_align": "left",
                            "type": "geomap",
                            "requests": [
                                {
                                    "response_format": "scalar",
                                    "queries": [
                                        {
                                            "name": "query1",
                                            "data_source": "logs",
                                            "search": {
                                                "query": "@network.client.geoip.country.iso_code:*"
                                            },
                                            "indexes": [
                                                "*"
                                            ],
                                            "group_by": [
                                                {
                                                    "facet": "@network.client.geoip.country.iso_code",
                                                    "limit": 50,
                                                    "sort": {
                                                        "aggregation": "count",
                                                        "order": "desc",
                                                        "metric": "count"
                                                    },
                                                    "should_exclude_missing": true
                                                }
                                            ],
                                            "compute": {
                                                "aggregation": "count"
                                            },
                                            "storage": "hot"
                                        }
                                    ],
                                    "formulas": [
                                        {
                                            "formula": "query1"
                                        }
                                    ],
                                    "sort": {
                                        "count": 50,
                                        "order_by": [
                                            {
                                                "type": "formula",
                                                "index": 0,
                                                "order": "desc"
                                            }
                                        ]
                                    }
                                }
                            ],
                            "style": {
                                "palette": "YlOrRd",
                                "palette_flip": false
                            },
                            "view": {
                                "focus": "WORLD"
                            }
                        },
                        "layout": {
                            "x": 0,
                            "y": 0,
                            "width": 6,
                            "height": 5
                        }
                    },
                    {
                        "id": 5748457744971301,
                        "definition": {
                            "title": "Malicious IPs by Country",
                            "title_size": "16",
                            "title_align": "left",
                            "type": "geomap",
                            "requests": [
                                {
                                    "response_format": "scalar",
                                    "queries": [
                                        {
                                            "search": {
                                                "query": "@threat_intel.indicators_matched:IP @threat_intel.results.intention:malicious"
                                            },
                                            "data_source": "logs",
                                            "compute": {
                                                "aggregation": "count"
                                            },
                                            "name": "query1",
                                            "storage": "hot",
                                            "indexes": [
                                                "*"
                                            ],
                                            "group_by": [
                                                {
                                                    "facet": "@network.client.geoip.country.iso_code",
                                                    "sort": {
                                                        "aggregation": "count",
                                                        "order": "desc"
                                                    },
                                                    "limit": 1000
                                                }
                                            ]
                                        }
                                    ],
                                    "formulas": [
                                        {
                                            "formula": "query1"
                                        }
                                    ],
                                    "sort": {
                                        "count": 1000,
                                        "order_by": [
                                            {
                                                "type": "formula",
                                                "index": 0,
                                                "order": "desc"
                                            }
                                        ]
                                    }
                                }
                            ],
                            "custom_links": [
                                {
                                    "link": "/security?query=@workflow.rule.type%3A(%22Log%20Detection%22%20OR%20%22Signal%20Correlation%22)%20{{@network.client.geoip.country.iso_code}}%20{{$network.client.ip}}%20{{$source}}%20{{$service}}%20{{$env}}&start={{timestamp_start}}&end={{timestamp_end}}&paused=true",
                                    "label": "View related Security Signals"
                                }
                            ],
                            "style": {
                                "palette": "YlOrRd",
                                "palette_flip": false
                            },
                            "view": {
                                "focus": "WORLD"
                            }
                        },
                        "layout": {
                            "x": 6,
                            "y": 0,
                            "width": 6,
                            "height": 5
                        }
                    },
                    {
                        "id": 4304014880816591,
                        "definition": {
                            "title": "Total Bytes Sent (2 weeks)",
                            "title_size": "16",
                            "title_align": "left",
                            "show_legend": true,
                            "legend_layout": "auto",
                            "legend_columns": [
                                "avg",
                                "min",
                                "max",
                                "value",
                                "sum"
                            ],
                            "time": {
                                "type": "live",
                                "unit": "week",
                                "value": 2
                            },
                            "type": "timeseries",
                            "requests": [
                                {
                                    "formulas": [
                                        {
                                            "formula": "query1"
                                        }
                                    ],
                                    "queries": [
                                        {
                                            "data_source": "metrics",
                                            "name": "query1",
                                            "query": "sum:system.net.bytes_sent{*}"
                                        }
                                    ],
                                    "response_format": "timeseries",
                                    "style": {
                                        "palette": "dog_classic",
                                        "order_by": "values",
                                        "line_type": "solid",
                                        "line_width": "normal"
                                    },
                                    "display_type": "line"
                                }
                            ]
                        },
                        "layout": {
                            "x": 0,
                            "y": 5,
                            "width": 6,
                            "height": 2
                        }
                    },
                    {
                        "id": 5806315844188016,
                        "definition": {
                            "title": "Total Bytes Received (2 weeks)",
                            "title_size": "16",
                            "title_align": "left",
                            "show_legend": true,
                            "legend_layout": "auto",
                            "legend_columns": [
                                "avg",
                                "min",
                                "max",
                                "value",
                                "sum"
                            ],
                            "time": {
                                "type": "live",
                                "unit": "week",
                                "value": 2
                            },
                            "type": "timeseries",
                            "requests": [
                                {
                                    "formulas": [
                                        {
                                            "formula": "query1"
                                        }
                                    ],
                                    "queries": [
                                        {
                                            "data_source": "metrics",
                                            "name": "query1",
                                            "query": "sum:system.net.bytes_rcvd{*}"
                                        }
                                    ],
                                    "response_format": "timeseries",
                                    "style": {
                                        "palette": "dog_classic",
                                        "order_by": "values",
                                        "line_type": "solid",
                                        "line_width": "normal"
                                    },
                                    "display_type": "line"
                                }
                            ]
                        },
                        "layout": {
                            "x": 6,
                            "y": 5,
                            "width": 6,
                            "height": 2
                        }
                    },
                    {
                        "id": 423451334418777,
                        "definition": {
                            "title": "% Change in Bytes Sent (1 Day)",
                            "title_size": "16",
                            "title_align": "left",
                            "time": {
                                "type": "live",
                                "unit": "day",
                                "value": 1
                            },
                            "type": "change",
                            "requests": [
                                {
                                    "increase_good": true,
                                    "order_by": "change",
                                    "change_type": "relative",
                                    "order_dir": "desc",
                                    "response_format": "scalar",
                                    "formulas": [
                                        {
                                            "formula": "day_before(query1)",
                                            "number_format": {
                                                "unit": {
                                                    "type": "canonical_unit",
                                                    "unit_name": "gigabyte",
                                                    "per_unit_name": "day"
                                                }
                                            }
                                        },
                                        {
                                            "formula": "query1"
                                        }
                                    ],
                                    "queries": [
                                        {
                                            "data_source": "metrics",
                                            "name": "query1",
                                            "query": "avg:system.net.bytes_sent{*}",
                                            "aggregator": "avg"
                                        }
                                    ],
                                    "show_present": false
                                }
                            ]
                        },
                        "layout": {
                            "x": 0,
                            "y": 7,
                            "width": 6,
                            "height": 2
                        }
                    },
                    {
                        "id": 3067083995091263,
                        "definition": {
                            "title": "% Change in Bytes Received (1 day)",
                            "title_size": "16",
                            "title_align": "left",
                            "time": {
                                "type": "live",
                                "unit": "day",
                                "value": 1
                            },
                            "type": "change",
                            "requests": [
                                {
                                    "increase_good": true,
                                    "order_by": "change",
                                    "change_type": "relative",
                                    "order_dir": "desc",
                                    "response_format": "scalar",
                                    "formulas": [
                                        {
                                            "formula": "day_before(query1)",
                                            "number_format": {
                                                "unit": {
                                                    "type": "canonical_unit",
                                                    "unit_name": "gigabyte",
                                                    "per_unit_name": "day"
                                                }
                                            }
                                        },
                                        {
                                            "formula": "query1"
                                        }
                                    ],
                                    "queries": [
                                        {
                                            "data_source": "metrics",
                                            "name": "query1",
                                            "query": "avg:system.net.bytes_rcvd{*}",
                                            "aggregator": "avg"
                                        }
                                    ],
                                    "show_present": false
                                }
                            ]
                        },
                        "layout": {
                            "x": 6,
                            "y": 7,
                            "width": 6,
                            "height": 2
                        }
                    },
                    {
                        "id": 7617103494783807,
                        "definition": {
                            "title": "Top Talkers by Bytes Sent (2 weeks)",
                            "title_size": "16",
                            "title_align": "left",
                            "time": {
                                "type": "live",
                                "unit": "week",
                                "value": 2
                            },
                            "type": "toplist",
                            "requests": [
                                {
                                    "queries": [
                                        {
                                            "data_source": "metrics",
                                            "name": "query1",
                                            "query": "avg:system.net.bytes_sent{*} by {host}",
                                            "aggregator": "avg"
                                        }
                                    ],
                                    "response_format": "scalar",
                                    "formulas": [
                                        {
                                            "formula": "query1",
                                            "number_format": {
                                                "unit": {
                                                    "type": "canonical_unit",
                                                    "unit_name": "megabyte",
                                                    "per_unit_name": "day"
                                                }
                                            }
                                        }
                                    ],
                                    "sort": {
                                        "count": 10,
                                        "order_by": [
                                            {
                                                "type": "formula",
                                                "index": 0,
                                                "order": "desc"
                                            }
                                        ]
                                    }
                                }
                            ],
                            "style": {
                                "display": {
                                    "type": "stacked",
                                    "legend": "automatic"
                                }
                            }
                        },
                        "layout": {
                            "x": 0,
                            "y": 9,
                            "width": 6,
                            "height": 2
                        }
                    },
                    {
                        "id": 6290082591741302,
                        "definition": {
                            "title": "Top Talkers by Bytes Received (2 weeks)",
                            "title_size": "16",
                            "title_align": "left",
                            "time": {
                                "type": "live",
                                "unit": "week",
                                "value": 2
                            },
                            "type": "toplist",
                            "requests": [
                                {
                                    "queries": [
                                        {
                                            "data_source": "metrics",
                                            "name": "query1",
                                            "query": "avg:system.net.bytes_rcvd{*} by {host}",
                                            "aggregator": "avg"
                                        }
                                    ],
                                    "response_format": "scalar",
                                    "formulas": [
                                        {
                                            "number_format": {
                                                "unit": {
                                                    "type": "canonical_unit",
                                                    "unit_name": "megabyte",
                                                    "per_unit_name": "day"
                                                }
                                            },
                                            "formula": "query1"
                                        }
                                    ],
                                    "sort": {
                                        "count": 10,
                                        "order_by": [
                                            {
                                                "type": "formula",
                                                "index": 0,
                                                "order": "desc"
                                            }
                                        ]
                                    }
                                }
                            ],
                            "style": {
                                "display": {
                                    "type": "stacked",
                                    "legend": "automatic"
                                }
                            }
                        },
                        "layout": {
                            "x": 6,
                            "y": 9,
                            "width": 6,
                            "height": 2
                        }
                    },
                    {
                        "id": 8748412767562548,
                        "definition": {
                            "title": "Top Talkers by Packets Sent (2 weeks)",
                            "title_size": "16",
                            "title_align": "left",
                            "time": {
                                "type": "live",
                                "unit": "week",
                                "value": 2
                            },
                            "type": "toplist",
                            "requests": [
                                {
                                    "queries": [
                                        {
                                            "data_source": "metrics",
                                            "name": "query1",
                                            "query": "avg:system.net.packets_out.count{*} by {host}",
                                            "aggregator": "avg"
                                        }
                                    ],
                                    "response_format": "scalar",
                                    "formulas": [
                                        {
                                            "number_format": {
                                                "unit": {
                                                    "type": "canonical_unit",
                                                    "unit_name": "packet",
                                                    "per_unit_name": "day"
                                                }
                                            },
                                            "formula": "query1"
                                        }
                                    ],
                                    "sort": {
                                        "count": 10,
                                        "order_by": [
                                            {
                                                "type": "formula",
                                                "index": 0,
                                                "order": "desc"
                                            }
                                        ]
                                    }
                                }
                            ],
                            "style": {
                                "display": {
                                    "type": "stacked",
                                    "legend": "automatic"
                                }
                            }
                        },
                        "layout": {
                            "x": 0,
                            "y": 11,
                            "width": 6,
                            "height": 2
                        }
                    },
                    {
                        "id": 4637753342494501,
                        "definition": {
                            "title": "Top Talkers by Packets Received (2 weeks)",
                            "title_size": "16",
                            "title_align": "left",
                            "time": {
                                "type": "live",
                                "unit": "week",
                                "value": 2
                            },
                            "type": "toplist",
                            "requests": [
                                {
                                    "queries": [
                                        {
                                            "data_source": "metrics",
                                            "name": "query1",
                                            "query": "avg:system.net.packets_in.count{*} by {host}",
                                            "aggregator": "avg"
                                        }
                                    ],
                                    "response_format": "scalar",
                                    "formulas": [
                                        {
                                            "number_format": {
                                                "unit": {
                                                    "type": "canonical_unit",
                                                    "unit_name": "packet",
                                                    "per_unit_name": "day"
                                                }
                                            },
                                            "formula": "query1"
                                        }
                                    ],
                                    "sort": {
                                        "count": 10,
                                        "order_by": [
                                            {
                                                "type": "formula",
                                                "index": 0,
                                                "order": "desc"
                                            }
                                        ]
                                    }
                                }
                            ],
                            "style": {
                                "display": {
                                    "type": "stacked",
                                    "legend": "automatic"
                                }
                            }
                        },
                        "layout": {
                            "x": 6,
                            "y": 11,
                            "width": 6,
                            "height": 2
                        }
                    }
                ]
            },
            "layout": {
                "x": 0,
                "y": 0,
                "width": 12,
                "height": 1,
                "is_column_break": true
            }
        },
        {
            "id": 4900536966957330,
            "definition": {
                "title": "Access Monitoring",
                "background_color": "yellow",
                "show_title": true,
                "type": "group",
                "layout_type": "ordered",
                "widgets": [
                    {
                        "id": 4065014976271129,
                        "definition": {
                            "title": "Logins by Country",
                            "title_size": "16",
                            "title_align": "left",
                            "type": "geomap",
                            "requests": [
                                {
                                    "response_format": "scalar",
                                    "queries": [
                                        {
                                            "name": "query1",
                                            "data_source": "logs",
                                            "search": {
                                                "query": "@network.client.geoip.country.iso_code:* (@action_id:(LGIF OR LGIS) OR @evt.name:(\"LOGIN SUCCES\" OR \"LOGIN FAILED\"))"
                                            },
                                            "indexes": [
                                                "*"
                                            ],
                                            "group_by": [
                                                {
                                                    "facet": "@network.client.geoip.country.iso_code",
                                                    "limit": 50,
                                                    "sort": {
                                                        "aggregation": "count",
                                                        "order": "desc",
                                                        "metric": "count"
                                                    },
                                                    "should_exclude_missing": true
                                                }
                                            ],
                                            "compute": {
                                                "aggregation": "count"
                                            },
                                            "storage": "hot"
                                        }
                                    ],
                                    "formulas": [
                                        {
                                            "formula": "query1"
                                        }
                                    ],
                                    "sort": {
                                        "count": 50,
                                        "order_by": [
                                            {
                                                "type": "formula",
                                                "index": 0,
                                                "order": "desc"
                                            }
                                        ]
                                    }
                                }
                            ],
                            "style": {
                                "palette": "YlOrRd",
                                "palette_flip": false
                            },
                            "view": {
                                "focus": "WORLD"
                            }
                        },
                        "layout": {
                            "x": 0,
                            "y": 0,
                            "width": 12,
                            "height": 5
                        }
                    },
                    {
                        "id": 6971256007526625,
                        "definition": {
                            "title": "Workstations - Successful Logins",
                            "title_size": "16",
                            "title_align": "left",
                            "type": "query_value",
                            "requests": [
                                {
                                    "formulas": [
                                        {
                                            "formula": "query1"
                                        }
                                    ],
                                    "conditional_formats": [
                                        {
                                            "comparator": ">",
                                            "palette": "white_on_green",
                                            "value": 0
                                        }
                                    ],
                                    "response_format": "scalar",
                                    "queries": [
                                        {
                                            "name": "query1",
                                            "data_source": "logs",
                                            "search": {
                                                "query": "(@evt.category:auth* @evt.outcome:(success OR SUCCESS) -@evt.name:user.authentication.slo)"
                                            },
                                            "indexes": [
                                                "*"
                                            ],
                                            "group_by": [],
                                            "compute": {
                                                "aggregation": "count"
                                            },
                                            "storage": "hot"
                                        }
                                    ]
                                }
                            ],
                            "precision": 0
                        },
                        "layout": {
                            "x": 0,
                            "y": 5,
                            "width": 4,
                            "height": 2
                        }
                    },
                    {
                        "id": 1552527216497261,
                        "definition": {
                            "title": "Workstations - Failed Logins",
                            "title_size": "16",
                            "title_align": "left",
                            "type": "query_value",
                            "requests": [
                                {
                                    "formulas": [
                                        {
                                            "formula": "query1"
                                        }
                                    ],
                                    "conditional_formats": [
                                        {
                                            "comparator": ">",
                                            "palette": "white_on_red",
                                            "value": 0
                                        }
                                    ],
                                    "response_format": "scalar",
                                    "queries": [
                                        {
                                            "name": "query1",
                                            "data_source": "logs",
                                            "search": {
                                                "query": "@evt.name:(user.authentication.* OR user.session.start OR -user.authentication.slo) @evt.outcome:(failure OR FAILURE)"
                                            },
                                            "indexes": [
                                                "*"
                                            ],
                                            "group_by": [],
                                            "compute": {
                                                "aggregation": "count"
                                            },
                                            "storage": "hot"
                                        }
                                    ]
                                }
                            ],
                            "precision": 0
                        },
                        "layout": {
                            "x": 4,
                            "y": 5,
                            "width": 4,
                            "height": 2
                        }
                    },
                    {
                        "id": 2146577724998281,
                        "definition": {
                            "title": "Top IPs with Failed Logins",
                            "title_size": "16",
                            "title_align": "left",
                            "type": "toplist",
                            "requests": [
                                {
                                    "response_format": "scalar",
                                    "queries": [
                                        {
                                            "name": "query2",
                                            "data_source": "logs",
                                            "search": {
                                                "query": "service:sql-server-lab (@action_id:LGIF OR evt.name:\"LOGIN FAILED\") -@network.ip.attributes.ip:(\"127.0.0.1\" OR (172.31*))"
                                            },
                                            "indexes": [
                                                "*"
                                            ],
                                            "group_by": [
                                                {
                                                    "facet": "@network.ip.attributes.ip",
                                                    "limit": 10,
                                                    "sort": {
                                                        "aggregation": "count",
                                                        "order": "desc",
                                                        "metric": "count"
                                                    },
                                                    "should_exclude_missing": true
                                                }
                                            ],
                                            "compute": {
                                                "aggregation": "count"
                                            },
                                            "storage": "hot"
                                        }
                                    ],
                                    "formulas": [
                                        {
                                            "formula": "query2"
                                        }
                                    ],
                                    "sort": {
                                        "count": 10,
                                        "order_by": [
                                            {
                                                "type": "formula",
                                                "index": 0,
                                                "order": "desc"
                                            }
                                        ]
                                    }
                                }
                            ],
                            "style": {}
                        },
                        "layout": {
                            "x": 8,
                            "y": 5,
                            "width": 4,
                            "height": 2
                        }
                    },
                    {
                        "id": 6237842416519929,
                        "definition": {
                            "title": "SQL Server - Successful Logins",
                            "title_size": "16",
                            "title_align": "left",
                            "type": "toplist",
                            "requests": [
                                {
                                    "queries": [
                                        {
                                            "name": "query1",
                                            "data_source": "logs",
                                            "search": {
                                                "query": "service:sql-server-lab (@evt.name:\"LOGIN SUCCEEDED\" OR action_id:LGIS)"
                                            },
                                            "indexes": [
                                                "*"
                                            ],
                                            "group_by": [
                                                {
                                                    "facet": "@db.user",
                                                    "limit": 10,
                                                    "sort": {
                                                        "aggregation": "count",
                                                        "order": "desc",
                                                        "metric": "count"
                                                    },
                                                    "should_exclude_missing": true
                                                }
                                            ],
                                            "compute": {
                                                "aggregation": "count"
                                            },
                                            "storage": "hot"
                                        }
                                    ],
                                    "response_format": "scalar",
                                    "conditional_formats": [
                                        {
                                            "comparator": ">",
                                            "value": 0,
                                            "palette": "white_on_green"
                                        }
                                    ],
                                    "formulas": [
                                        {
                                            "formula": "query1"
                                        }
                                    ],
                                    "sort": {
                                        "count": 10,
                                        "order_by": [
                                            {
                                                "type": "formula",
                                                "index": 0,
                                                "order": "desc"
                                            }
                                        ]
                                    }
                                }
                            ],
                            "style": {
                                "display": {
                                    "type": "stacked",
                                    "legend": "automatic"
                                }
                            }
                        },
                        "layout": {
                            "x": 0,
                            "y": 7,
                            "width": 4,
                            "height": 2
                        }
                    },
                    {
                        "id": 379310769715114,
                        "definition": {
                            "title": "SQL Server - Failed Logins",
                            "title_size": "16",
                            "title_align": "left",
                            "type": "toplist",
                            "requests": [
                                {
                                    "queries": [
                                        {
                                            "name": "query1",
                                            "data_source": "logs",
                                            "search": {
                                                "query": "service:sql-server-lab (@action_id:LGIF OR @evt.name:\"LOGIN FAILED\")"
                                            },
                                            "indexes": [
                                                "*"
                                            ],
                                            "group_by": [
                                                {
                                                    "facet": "@server_principal_name",
                                                    "limit": 10,
                                                    "sort": {
                                                        "aggregation": "count",
                                                        "order": "desc",
                                                        "metric": "count"
                                                    }
                                                }
                                            ],
                                            "compute": {
                                                "aggregation": "count"
                                            },
                                            "storage": "hot"
                                        }
                                    ],
                                    "response_format": "scalar",
                                    "conditional_formats": [
                                        {
                                            "comparator": ">",
                                            "value": 0,
                                            "palette": "white_on_red"
                                        }
                                    ],
                                    "formulas": [
                                        {
                                            "formula": "query1"
                                        }
                                    ],
                                    "sort": {
                                        "count": 10,
                                        "order_by": [
                                            {
                                                "type": "formula",
                                                "index": 0,
                                                "order": "desc"
                                            }
                                        ]
                                    }
                                }
                            ],
                            "style": {
                                "display": {
                                    "type": "stacked",
                                    "legend": "automatic"
                                }
                            }
                        },
                        "layout": {
                            "x": 4,
                            "y": 7,
                            "width": 4,
                            "height": 2
                        }
                    },
                    {
                        "id": 7975815203026288,
                        "definition": {
                            "title": "Total - Logins by Outcome",
                            "title_size": "16",
                            "title_align": "left",
                            "show_legend": false,
                            "legend_layout": "auto",
                            "legend_columns": [
                                "avg",
                                "min",
                                "max",
                                "value",
                                "sum"
                            ],
                            "time": {
                                "type": "live",
                                "unit": "week",
                                "value": 2
                            },
                            "type": "timeseries",
                            "requests": [
                                {
                                    "formulas": [
                                        {
                                            "formula": "query1"
                                        }
                                    ],
                                    "queries": [
                                        {
                                            "name": "query1",
                                            "data_source": "logs",
                                            "search": {
                                                "query": "(@evt.name:*auth* @evt.outcome:(success OR SUCCESS)) OR (service:sql-server-lab @action_id:LGIS)"
                                            },
                                            "indexes": [
                                                "*"
                                            ],
                                            "group_by": [
                                                {
                                                    "facet": "@action_id",
                                                    "limit": 10,
                                                    "sort": {
                                                        "aggregation": "count",
                                                        "order": "desc",
                                                        "metric": "count"
                                                    }
                                                }
                                            ],
                                            "compute": {
                                                "aggregation": "count",
                                                "interval": 300000
                                            },
                                            "storage": "hot"
                                        }
                                    ],
                                    "response_format": "timeseries",
                                    "style": {
                                        "palette": "green",
                                        "line_type": "solid",
                                        "line_width": "normal"
                                    },
                                    "display_type": "line"
                                },
                                {
                                    "formulas": [
                                        {
                                            "formula": "query1"
                                        }
                                    ],
                                    "queries": [
                                        {
                                            "name": "query1",
                                            "data_source": "logs",
                                            "search": {
                                                "query": "(@evt.name:*auth* AND @evt.outcome:(failure OR FAILURE)) OR (service:sql-server-lab @action_id:LGIF)"
                                            },
                                            "indexes": [
                                                "*"
                                            ],
                                            "group_by": [
                                                {
                                                    "facet": "@action_id",
                                                    "limit": 10,
                                                    "sort": {
                                                        "aggregation": "count",
                                                        "order": "desc",
                                                        "metric": "count"
                                                    }
                                                }
                                            ],
                                            "compute": {
                                                "aggregation": "count",
                                                "interval": 300000
                                            },
                                            "storage": "hot"
                                        }
                                    ],
                                    "response_format": "timeseries",
                                    "style": {
                                        "palette": "warm",
                                        "line_type": "solid",
                                        "line_width": "normal"
                                    },
                                    "display_type": "line"
                                }
                            ],
                            "yaxis": {
                                "include_zero": true,
                                "scale": "linear",
                                "label": "",
                                "min": "auto",
                                "max": "auto"
                            },
                            "markers": []
                        },
                        "layout": {
                            "x": 8,
                            "y": 7,
                            "width": 4,
                            "height": 2
                        }
                    },
                    {
                        "id": 2616500835807434,
                        "definition": {
                            "title": "Admin Accounts - Successful Logins",
                            "title_size": "16",
                            "title_align": "left",
                            "type": "query_value",
                            "requests": [
                                {
                                    "formulas": [
                                        {
                                            "formula": "query1"
                                        }
                                    ],
                                    "conditional_formats": [
                                        {
                                            "comparator": ">",
                                            "palette": "white_on_green",
                                            "value": 0
                                        }
                                    ],
                                    "response_format": "scalar",
                                    "queries": [
                                        {
                                            "name": "query1",
                                            "data_source": "logs",
                                            "search": {
                                                "query": "service:* ((@evt.name:(user.authentication.* OR user.session.start OR -user.authentication.slo) @evt.outcome:(failure OR FAILURE) @usr.id:admin*) OR (action_id:LGIS @server_principal_name:*admin*))"
                                            },
                                            "indexes": [
                                                "*"
                                            ],
                                            "group_by": [],
                                            "compute": {
                                                "aggregation": "count"
                                            },
                                            "storage": "hot"
                                        }
                                    ]
                                }
                            ],
                            "precision": 0
                        },
                        "layout": {
                            "x": 0,
                            "y": 9,
                            "width": 4,
                            "height": 2
                        }
                    },
                    {
                        "id": 7306362952138603,
                        "definition": {
                            "title": "Admin Accounts - Failed Logins",
                            "title_size": "16",
                            "title_align": "left",
                            "type": "toplist",
                            "requests": [
                                {
                                    "queries": [
                                        {
                                            "name": "query1",
                                            "data_source": "logs",
                                            "search": {
                                                "query": "service:* ((@evt.name:(user.authentication.* OR user.session.start OR -user.authentication.slo) @evt.outcome:(failure OR FAILURE) @usr.id:admin*) OR (action_id:LGIF @server_principal_name:*admin*))"
                                            },
                                            "indexes": [
                                                "*"
                                            ],
                                            "group_by": [
                                                {
                                                    "facet": "host",
                                                    "limit": 10,
                                                    "sort": {
                                                        "aggregation": "count",
                                                        "order": "desc",
                                                        "metric": "count"
                                                    },
                                                    "should_exclude_missing": true
                                                }
                                            ],
                                            "compute": {
                                                "aggregation": "count"
                                            },
                                            "storage": "hot"
                                        }
                                    ],
                                    "response_format": "scalar",
                                    "conditional_formats": [
                                        {
                                            "comparator": ">",
                                            "palette": "white_on_red",
                                            "value": 0
                                        }
                                    ],
                                    "formulas": [
                                        {
                                            "formula": "query1"
                                        }
                                    ],
                                    "sort": {
                                        "count": 10,
                                        "order_by": [
                                            {
                                                "type": "formula",
                                                "index": 0,
                                                "order": "desc"
                                            }
                                        ]
                                    }
                                }
                            ],
                            "style": {
                                "display": {
                                    "type": "stacked",
                                    "legend": "automatic"
                                }
                            }
                        },
                        "layout": {
                            "x": 4,
                            "y": 9,
                            "width": 4,
                            "height": 2
                        }
                    }
                ]
            },
            "layout": {
                "x": 0,
                "y": 1,
                "width": 12,
                "height": 1
            }
        }
    ],
    "template_variables": [],
    "layout_type": "ordered",
    "notify_list": [],
    "reflow_type": "fixed",
    "tags": []
}
EOF
}