import dash
from dash import dcc, html, Input, Output, State
import plotly.graph_objs as go
import plotly.express as px
import pandas as pd
import threading
import time
from datetime import datetime, timedelta
from src.packet_capture import PacketCapture
from src.data_processor import DataProcessor
from src.anomaly_detector import AnomalyDetector
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class NetworkDashboard:
    def __init__(self, interface='eth0'):
        """Initialize the dashboard"""
        self.interface = interface
        self.app = dash.Dash(__name__)
        self.capture_thread = None
        self.is_capturing = False
        self.packet_buffer = []
        self.anomaly_detector = None
        
        # Load pre-trained model if exists
        try:
            self.anomaly_detector = AnomalyDetector()
            self.anomaly_detector.load_model()
            logger.info("Loaded pre-trained anomaly detection model")
        except:
            logger.warning("No pre-trained model found. Will train on first capture.")
        
        self.setup_layout()
        self.setup_callbacks()
    
    def setup_layout(self):
        """Setup enhanced dashboard layout"""
        self.app.layout = html.Div([
            # Header
            html.Div([
                html.H1([
                    html.Span("🛡️ ", style={'marginRight': '10px'}),
                    "Network Traffic Analyzer"
                ], style={
                    'margin': 0,
                    'fontSize': '32px',
                    'fontWeight': '700',
                    'color': '#1a202c'
                }),
                html.P("Real-time traffic monitoring with ML-based anomaly detection", 
                       style={'margin': '5px 0 0 0', 'color': '#718096', 'fontSize': '14px'})
            ], style={
                'padding': '30px 40px',
                'background': 'white',
                'borderBottom': '1px solid #e2e8f0',
                'marginBottom': '30px',
                'textAlign': 'center'
            }),
            
            # Control Panel
            html.Div([
                html.Div([
                    html.Label("Network Interface:", style={
                        'fontSize': '14px',
                        'fontWeight': '600',
                        'color': '#4a5568',
                        'marginRight': '10px'
                    }),
                    dcc.Input(id='interface-input', type='text', value=self.interface, 
                             style={
                                 'padding': '8px 12px',
                                 'border': '1px solid #cbd5e0',
                                 'borderRadius': '6px',
                                 'fontSize': '14px',
                                 'marginRight': '20px'
                             }),
                    html.Button('▶ Start Capture', id='start-btn', n_clicks=0, 
                               style={
                                   'padding': '8px 20px',
                                   'marginRight': '10px',
                                   'backgroundColor': '#48bb78',
                                   'color': 'white',
                                   'border': 'none',
                                   'borderRadius': '6px',
                                   'fontSize': '14px',
                                   'fontWeight': '600',
                                   'cursor': 'pointer'
                               }),
                    html.Button('■ Stop Capture', id='stop-btn', n_clicks=0,
                               style={
                                   'padding': '8px 20px',
                                   'marginRight': '10px',
                                   'backgroundColor': '#f56565',
                                   'color': 'white',
                                   'border': 'none',
                                   'borderRadius': '6px',
                                   'fontSize': '14px',
                                   'fontWeight': '600',
                                   'cursor': 'pointer'
                               }),
                    html.Button('🤖 Train Model', id='train-btn', n_clicks=0,
                               style={
                                   'padding': '8px 20px',
                                   'backgroundColor': '#4299e1',
                                   'color': 'white',
                                   'border': 'none',
                                   'borderRadius': '6px',
                                   'fontSize': '14px',
                                   'fontWeight': '600',
                                   'cursor': 'pointer'
                               }),
                ], style={'padding': 20, 'backgroundColor': 'white', 'borderRadius': '8px', 'boxShadow': '0 1px 3px rgba(0,0,0,0.1)'}),
                
                html.Div(id='status-output', style={'marginTop': 15, 'padding': '12px', 'borderRadius': '6px'})
            ], style={'margin': '0 40px 30px 40px'}),
            
            # Statistics Cards
            html.Div([
                # Total Packets Card
                html.Div([
                    html.Div("📊", style={'fontSize': '32px', 'marginBottom': '10px'}),
                    html.H2(id='total-packets', children='0', style={
                        'margin': '0 0 4px 0',
                        'fontSize': '40px',
                        'fontWeight': '700',
                        'color': '#ffffff'
                    }),
                    html.P('Total Packets', style={
                        'margin': 0,
                        'color': '#e6e6e6',
                        'fontSize': '13px',
                        'fontWeight': '500',
                        'textTransform': 'uppercase',
                        'letterSpacing': '0.5px'
                    })
                ], style={
                    'flex': '1',
                    'padding': '30px',
                    'background': 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
                    'color': 'white',
                    'borderRadius': '12px',
                    'margin': '0 12px',
                    'boxShadow': '0 4px 6px rgba(0,0,0,0.15)',
                    'minWidth': '200px',
                    'textAlign': 'center'
                }),
                
                # Anomalies Card
                html.Div([
                    html.Div("⚠️", style={'fontSize': '32px', 'marginBottom': '10px'}),
                    html.H2(id='anomaly-count', children='0', style={
                        'margin': '0 0 4px 0',
                        'fontSize': '40px',
                        'fontWeight': '700',
                        'color': '#ffffff'
                    }),
                    html.P('Anomalies Detected', style={
                        'margin': 0,
                        'color': '#e6e6e6',
                        'fontSize': '13px',
                        'fontWeight': '500',
                        'textTransform': 'uppercase',
                        'letterSpacing': '0.5px'
                    })
                ], style={
                    'flex': '1',
                    'padding': '30px',
                    'background': 'linear-gradient(135deg, #f093fb 0%, #f5576c 100%)',
                    'color': 'white',
                    'borderRadius': '12px',
                    'margin': '0 12px',
                    'boxShadow': '0 4px 6px rgba(0,0,0,0.15)',
                    'minWidth': '200px',
                    'textAlign': 'center'
                }),
                
                # Unique IPs Card
                html.Div([
                    html.Div("🌐", style={'fontSize': '32px', 'marginBottom': '10px'}),
                    html.H2(id='unique-ips', children='0', style={
                        'margin': '0 0 4px 0',
                        'fontSize': '40px',
                        'fontWeight': '700',
                        'color': '#ffffff'
                    }),
                    html.P('Unique IP Addresses', style={
                        'margin': 0,
                        'color': '#e6e6e6',
                        'fontSize': '13px',
                        'fontWeight': '500',
                        'textTransform': 'uppercase',
                        'letterSpacing': '0.5px'
                    })
                ], style={
                    'flex': '1',
                    'padding': '30px',
                    'background': 'linear-gradient(135deg, #4facfe 0%, #00f2fe 100%)',
                    'color': 'white',
                    'borderRadius': '12px',
                    'margin': '0 12px',
                    'boxShadow': '0 4px 6px rgba(0,0,0,0.15)',
                    'minWidth': '200px',
                    'textAlign': 'center'
                }),
                
                # Traffic Rate Card
                html.Div([
                    html.Div("⚡", style={'fontSize': '32px', 'marginBottom': '10px'}),
                    html.H2(id='traffic-rate', children='0 KB/s', style={
                        'margin': '0 0 4px 0',
                        'fontSize': '40px',
                        'fontWeight': '700',
                        'color': '#ffffff'
                    }),
                    html.P('Traffic Rate', style={
                        'margin': 0,
                        'color': '#e6e6e6',
                        'fontSize': '13px',
                        'fontWeight': '500',
                        'textTransform': 'uppercase',
                        'letterSpacing': '0.5px'
                    })
                ], style={
                    'flex': '1',
                    'padding': '30px',
                    'background': 'linear-gradient(135deg, #fa709a 0%, #fee140 100%)',
                    'color': 'white',
                    'borderRadius': '12px',
                    'margin': '0 12px',
                    'boxShadow': '0 4px 6px rgba(0,0,0,0.15)',
                    'minWidth': '200px',
                    'textAlign': 'center'
                }),
            ], style={'display': 'flex', 'flexWrap': 'wrap', 'margin': '0 28px 30px 28px'}),
            
            # Graphs Row 1
            html.Div([
                html.Div([
                    dcc.Graph(id='protocol-pie-chart', config={'displayModeBar': False})
                ], style={
                    'flex': '1',
                    'background': 'white',
                    'borderRadius': '12px',
                    'padding': '20px',
                    'margin': '0 12px',
                    'boxShadow': '0 1px 3px rgba(0,0,0,0.1)'
                }),
                
                html.Div([
                    dcc.Graph(id='traffic-timeline', config={'displayModeBar': False})
                ], style={
                    'flex': '1',
                    'background': 'white',
                    'borderRadius': '12px',
                    'padding': '20px',
                    'margin': '0 12px',
                    'boxShadow': '0 1px 3px rgba(0,0,0,0.1)'
                }),
            ], style={'display': 'flex', 'margin': '0 28px 25px 28px'}),
            
            # Graphs Row 2
            html.Div([
                html.Div([
                    dcc.Graph(id='top-talkers', config={'displayModeBar': False})
                ], style={
                    'flex': '1',
                    'background': 'white',
                    'borderRadius': '12px',
                    'padding': '20px',
                    'margin': '0 12px',
                    'boxShadow': '0 1px 3px rgba(0,0,0,0.1)'
                }),
                
                html.Div([
                    dcc.Graph(id='anomaly-scatter', config={'displayModeBar': False})
                ], style={
                    'flex': '1',
                    'background': 'white',
                    'borderRadius': '12px',
                    'padding': '20px',
                    'margin': '0 12px',
                    'boxShadow': '0 1px 3px rgba(0,0,0,0.1)'
                }),
            ], style={'display': 'flex', 'margin': '0 28px 25px 28px'}),
            
            # Anomaly Table
            html.Div([
                html.H3("🔍 Recent Anomalies", style={
                    'margin': '0 0 20px 0',
                    'fontSize': '20px',
                    'fontWeight': '600',
                    'color': '#1a202c'
                }),
                html.Div(id='anomaly-table', style={'overflowX': 'auto'})
            ], style={
                'margin': '0 40px 40px 40px',
                'padding': '30px',
                'background': 'white',
                'borderRadius': '12px',
                'boxShadow': '0 1px 3px rgba(0,0,0,0.1)'
            }),
            
            # Auto-refresh interval
            dcc.Interval(
                id='interval-component',
                interval=2*1000,
                n_intervals=0
            ),
            
            # Store data
            dcc.Store(id='packet-data-store', data=[])
        ], style={
            'fontFamily': "'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif",
            'background': '#f7fafc',
            'minHeight': '100vh',
            'padding': '0',
            'margin': '0'
        })
    
    def setup_callbacks(self):
        """Setup dashboard callbacks"""
        
        @self.app.callback(
            Output('status-output', 'children'),
            Output('packet-data-store', 'data'),
            Input('start-btn', 'n_clicks'),
            Input('stop-btn', 'n_clicks'),
            Input('train-btn', 'n_clicks'),
            State('interface-input', 'value'),
            prevent_initial_call=True
        )
        def control_capture(start_clicks, stop_clicks, train_clicks, interface):
            ctx = dash.callback_context
            
            if not ctx.triggered:
                return "", []
            
            button_id = ctx.triggered[0]['prop_id'].split('.')[0]
            
            if button_id == 'start-btn':
                if not self.is_capturing:
                    self.interface = interface
                    self.start_capture_thread()
                    return html.Div("✓ Capture started successfully", style={
                        'color': '#22543d',
                        'backgroundColor': '#c6f6d5',
                        'padding': '10px 15px',
                        'borderRadius': '6px',
                        'border': '1px solid #9ae6b4',
                        'fontWeight': '600'
                    }), []
                return html.Div("⚠ Already capturing", style={
                    'color': '#7c2d12',
                    'backgroundColor': '#feebc8',
                    'padding': '10px 15px',
                    'borderRadius': '6px',
                    'border': '1px solid #fbd38d',
                    'fontWeight': '600'
                }), []
            
            elif button_id == 'stop-btn':
                if self.is_capturing:
                    self.stop_capture_thread()
                    return html.Div("✓ Capture stopped", style={
                        'color': '#742a2a',
                        'backgroundColor': '#fed7d7',
                        'padding': '10px 15px',
                        'borderRadius': '6px',
                        'border': '1px solid #fc8181',
                        'fontWeight': '600'
                    }), []
                return html.Div("⚠ Not currently capturing", style={
                    'color': '#7c2d12',
                    'backgroundColor': '#feebc8',
                    'padding': '10px 15px',
                    'borderRadius': '6px',
                    'border': '1px solid #fbd38d',
                    'fontWeight': '600'
                }), []
            
            elif button_id == 'train-btn':
                if len(self.packet_buffer) > 100:
                    self.train_model()
                    return html.Div("✓ Model trained successfully!", style={
                        'color': '#2c5282',
                        'backgroundColor': '#bee3f8',
                        'padding': '10px 15px',
                        'borderRadius': '6px',
                        'border': '1px solid #90cdf4',
                        'fontWeight': '600'
                    }), []
                return html.Div(f"⚠ Need at least 100 packets to train (currently have {len(self.packet_buffer)})", style={
                    'color': '#7c2d12',
                    'backgroundColor': '#feebc8',
                    'padding': '10px 15px',
                    'borderRadius': '6px',
                    'border': '1px solid #fbd38d',
                    'fontWeight': '600'
                }), []
            
            return "", []
        
        @self.app.callback(
            [Output('total-packets', 'children'),
             Output('anomaly-count', 'children'),
             Output('unique-ips', 'children'),
             Output('traffic-rate', 'children'),
             Output('protocol-pie-chart', 'figure'),
             Output('traffic-timeline', 'figure'),
             Output('top-talkers', 'figure'),
             Output('anomaly-scatter', 'figure'),
             Output('anomaly-table', 'children')],
            Input('interval-component', 'n_intervals')
        )
        def update_dashboard(n):
            if len(self.packet_buffer) == 0:
                empty_fig = go.Figure()
                empty_fig.update_layout(
                    title="No data yet - Start capturing to see results",
                    paper_bgcolor='white',
                    plot_bgcolor='white',
                    font={'color': '#718096', 'size': 14}
                )
                return '0', '0', '0', '0 KB/s', empty_fig, empty_fig, empty_fig, empty_fig, html.P("No anomalies detected yet", style={'color': '#a0aec0', 'textAlign': 'center', 'padding': '40px'})
            
            df = pd.DataFrame(self.packet_buffer)
            processor = DataProcessor(df)
            df_processed = processor.extract_features()
            
            # Detect anomalies
            anomaly_count = 0
            if self.anomaly_detector and self.anomaly_detector.model:
                try:
                    X, _ = processor.prepare_ml_features()
                    predictions = self.anomaly_detector.predict(X)
                    scores = self.anomaly_detector.get_anomaly_scores(X)
                    df_processed['is_anomaly'] = predictions
                    df_processed['anomaly_score'] = scores
                    anomaly_count = len(df_processed[df_processed['is_anomaly'] == -1])
                except Exception as e:
                    logger.error(f"Error detecting anomalies: {e}")
                    df_processed['is_anomaly'] = 1
                    df_processed['anomaly_score'] = 0
            
            # Statistics
            total_packets = len(df_processed)
            unique_ips = df_processed['src_ip'].nunique() + df_processed['dst_ip'].nunique()
            
            # Traffic rate
            if 'timestamp' in df_processed.columns and len(df_processed) > 1:
                df_processed['timestamp'] = pd.to_datetime(df_processed['timestamp'])
                time_span = (df_processed['timestamp'].max() - df_processed['timestamp'].min()).total_seconds()
                if time_span > 0:
                    bytes_per_sec = df_processed['length'].sum() / time_span
                    traffic_rate = f"{bytes_per_sec / 1024:.1f}"
                else:
                    traffic_rate = "0"
            else:
                traffic_rate = "0"
            
            # Protocol Pie Chart
            protocol_counts = df_processed['protocol_name'].value_counts()
            pie_fig = go.Figure(data=[go.Pie(
                labels=protocol_counts.index,
                values=protocol_counts.values,
                hole=0.4,
                marker=dict(colors=['#667eea', '#764ba2', '#f093fb', '#f5576c', '#4facfe'])
            )])
            pie_fig.update_layout(
                title={'text': 'Protocol Distribution', 'font': {'size': 18, 'color': '#2d3748', 'family': 'Inter'}},
                paper_bgcolor='white',
                plot_bgcolor='white',
                showlegend=True,
                height=350,
                margin=dict(t=50, b=20, l=20, r=20)
            )
            
            # Traffic Timeline
            if 'timestamp' in df_processed.columns:
                df_timeline = df_processed.groupby(pd.Grouper(key='timestamp', freq='10s')).size().reset_index(name='count')
                timeline_fig = go.Figure(data=[go.Scatter(
                    x=df_timeline['timestamp'],
                    y=df_timeline['count'],
                    mode='lines',
                    fill='tozeroy',
                    line=dict(color='#4299e1', width=2),
                    fillcolor='rgba(66, 153, 225, 0.2)'
                )])
                timeline_fig.update_layout(
                    title={'text': 'Traffic Over Time (10s intervals)', 'font': {'size': 18, 'color': '#2d3748', 'family': 'Inter'}},
                    xaxis_title="Time",
                    yaxis_title="Packets",
                    paper_bgcolor='white',
                    plot_bgcolor='white',
                    height=350,
                    margin=dict(t=50, b=50, l=50, r=20),
                    xaxis=dict(showgrid=True, gridcolor='#e2e8f0'),
                    yaxis=dict(showgrid=True, gridcolor='#e2e8f0')
                )
            else:
                timeline_fig = go.Figure()
                timeline_fig.update_layout(
                    title="Traffic Over Time",
                    paper_bgcolor='white',
                    plot_bgcolor='white'
                )
            
            # Top Talkers
            top_src = df_processed['src_ip'].value_counts().head(10)
            talkers_fig = go.Figure(data=[go.Bar(
                x=top_src.values,
                y=top_src.index,
                orientation='h',
                marker=dict(
                    color=top_src.values,
                    colorscale='Viridis',
                    showscale=False
                )
            )])
            talkers_fig.update_layout(
                title={'text': 'Top 10 Source IPs', 'font': {'size': 18, 'color': '#2d3748', 'family': 'Inter'}},
                xaxis_title="Packet Count",
                yaxis_title="IP Address",
                paper_bgcolor='white',
                plot_bgcolor='white',
                height=350,
                margin=dict(t=50, b=50, l=150, r=20),
                xaxis=dict(showgrid=True, gridcolor='#e2e8f0'),
                yaxis=dict(showgrid=False)
            )
            
            # Anomaly Scatter
            if 'is_anomaly' in df_processed.columns:
                scatter_df = df_processed.copy()
                scatter_df['status'] = scatter_df['is_anomaly'].map({1: 'Normal', -1: 'Anomaly'})
                scatter_fig = go.Figure()
                
                # Normal points
                normal = scatter_df[scatter_df['status'] == 'Normal']
                scatter_fig.add_trace(go.Scatter(
                    x=normal['length'],
                    y=normal['anomaly_score'],
                    mode='markers',
                    name='Normal',
                    marker=dict(color='#48bb78', size=6, opacity=0.6)
                ))
                
                # Anomaly points
                anomalies_plot = scatter_df[scatter_df['status'] == 'Anomaly']
                scatter_fig.add_trace(go.Scatter(
                    x=anomalies_plot['length'],
                    y=anomalies_plot['anomaly_score'],
                    mode='markers',
                    name='Anomaly',
                    marker=dict(color='#f56565', size=10, symbol='x')
                ))
                
                scatter_fig.update_layout(
                    title={'text': 'Anomaly Detection', 'font': {'size': 18, 'color': '#2d3748', 'family': 'Inter'}},
                    xaxis_title="Packet Size (bytes)",
                    yaxis_title="Anomaly Score",
                    paper_bgcolor='white',
                    plot_bgcolor='white',
                    height=350,
                    margin=dict(t=50, b=50, l=50, r=20),
                    xaxis=dict(showgrid=True, gridcolor='#e2e8f0'),
                    yaxis=dict(showgrid=True, gridcolor='#e2e8f0'),
                    showlegend=True
                )
            else:
                scatter_fig = go.Figure()
                scatter_fig.update_layout(
                    title="Train the model to see anomaly detection",
                    paper_bgcolor='white',
                    plot_bgcolor='white',
                    font={'color': '#718096'}
                )
            
            # Anomaly Table
            if 'is_anomaly' in df_processed.columns:
                anomalies = df_processed[df_processed['is_anomaly'] == -1].nsmallest(10, 'anomaly_score')
                if len(anomalies) > 0:
                    table = html.Table([
                        html.Thead(html.Tr([
                            html.Th('Timestamp', style={'padding': '12px', 'textAlign': 'left', 'borderBottom': '2px solid #e2e8f0', 'color': '#4a5568', 'fontSize': '13px', 'fontWeight': '600', 'backgroundColor': '#f7fafc'}),
                            html.Th('Source IP', style={'padding': '12px', 'textAlign': 'left', 'borderBottom': '2px solid #e2e8f0', 'color': '#4a5568', 'fontSize': '13px', 'fontWeight': '600', 'backgroundColor': '#f7fafc'}),
                            html.Th('Dest IP', style={'padding': '12px', 'textAlign': 'left', 'borderBottom': '2px solid #e2e8f0', 'color': '#4a5568', 'fontSize': '13px', 'fontWeight': '600', 'backgroundColor': '#f7fafc'}),
                            html.Th('Protocol', style={'padding': '12px', 'textAlign': 'left', 'borderBottom': '2px solid #e2e8f0', 'color': '#4a5568', 'fontSize': '13px', 'fontWeight': '600', 'backgroundColor': '#f7fafc'}),
                            html.Th('Size', style={'padding': '12px', 'textAlign': 'left', 'borderBottom': '2px solid #e2e8f0', 'color': '#4a5568', 'fontSize': '13px', 'fontWeight': '600', 'backgroundColor': '#f7fafc'}),
                            html.Th('Anomaly Score', style={'padding': '12px', 'textAlign': 'left', 'borderBottom': '2px solid #e2e8f0', 'color': '#4a5568', 'fontSize': '13px', 'fontWeight': '600', 'backgroundColor': '#f7fafc'})
                        ])),
                        html.Tbody([
                            html.Tr([
                                html.Td(str(row['timestamp'])[:19] if 'timestamp' in row else 'N/A', style={'padding': '12px', 'borderBottom': '1px solid #f7fafc', 'fontSize': '13px', 'color': '#2d3748'}),
                                html.Td(row['src_ip'], style={'padding': '12px', 'borderBottom': '1px solid #f7fafc', 'fontSize': '13px', 'color': '#2d3748', 'fontFamily': 'monospace'}),
                                html.Td(row['dst_ip'], style={'padding': '12px', 'borderBottom': '1px solid #f7fafc', 'fontSize': '13px', 'color': '#2d3748', 'fontFamily': 'monospace'}),
                                html.Td(html.Span(row['protocol_name'], style={'padding': '4px 10px', 'background': '#edf2f7', 'borderRadius': '4px', 'fontSize': '12px', 'fontWeight': '600', 'color': '#4a5568'}), style={'padding': '12px', 'borderBottom': '1px solid #f7fafc'}),
                                html.Td(f"{row['length']} bytes", style={'padding': '12px', 'borderBottom': '1px solid #f7fafc', 'fontSize': '13px', 'color': '#2d3748'}),
                                html.Td(html.Span(f"{row['anomaly_score']:.4f}", style={'padding': '4px 10px', 'background': '#fed7d7', 'color': '#c53030', 'borderRadius': '4px', 'fontSize': '12px', 'fontWeight': '700'}), style={'padding': '12px', 'borderBottom': '1px solid #f7fafc'})
                            ]) for idx, row in anomalies.iterrows()
                        ])
                    ], style={'width': '100%', 'borderCollapse': 'collapse'})
                else:
                    table = html.P("No anomalies detected", style={'color': '#a0aec0', 'textAlign': 'center', 'padding': '40px', 'fontSize': '14px'})
            else:
                table = html.P("Train the model to detect anomalies", style={'color': '#a0aec0', 'textAlign': 'center', 'padding': '40px', 'fontSize': '14px'})
            
            return (
                f"{total_packets:,}",
                str(anomaly_count),
                str(unique_ips),
                f"{traffic_rate} KB/s",
                pie_fig,
                timeline_fig,
                talkers_fig,
                scatter_fig,
                table
            )
    
    def capture_packets_continuously(self):
        """Continuously capture packets in background"""
        logger.info("Starting continuous packet capture")
        
        from scapy.all import sniff
        
        def packet_handler(packet):
            if not self.is_capturing:
                return
            
            capturer = PacketCapture(self.interface)
            capturer.packet_callback(packet)
            
            if capturer.packets_data:
                self.packet_buffer.extend(capturer.packets_data)
                
                if len(self.packet_buffer) > 10000:
                    self.packet_buffer = self.packet_buffer[-10000:]
        
        try:
            sniff(iface=self.interface, prn=packet_handler, store=False, 
                  stop_filter=lambda x: not self.is_capturing)
        except Exception as e:
            logger.error(f"Error in packet capture: {e}")
            self.is_capturing = False
    
    def start_capture_thread(self):
        """Start packet capture in background thread"""
        if not self.is_capturing:
            self.is_capturing = True
            self.capture_thread = threading.Thread(target=self.capture_packets_continuously, daemon=True)
            self.capture_thread.start()
            logger.info("Packet capture thread started")
    
    def stop_capture_thread(self):
        """Stop packet capture"""
        self.is_capturing = False
        if self.capture_thread:
            self.capture_thread.join(timeout=5)
        logger.info("Packet capture stopped")
    
    def train_model(self):
        """Train anomaly detection model on captured data"""
        logger.info("Training anomaly detection model...")
        
        df = pd.DataFrame(self.packet_buffer)
        processor = DataProcessor(df)
        df_processed = processor.extract_features()
        X, feature_names = processor.prepare_ml_features()
        
        self.anomaly_detector = AnomalyDetector(model_type='isolation_forest')
        self.anomaly_detector.feature_names = feature_names
        self.anomaly_detector.train(X, contamination=0.05)
        self.anomaly_detector.save_model()
        
        logger.info("Model training completed and saved")
    
    def run(self, debug=False, port=8050):
        """Run the dashboard"""
        logger.info(f"Starting dashboard on port {port}")
        self.app.run(debug=debug, port=port, host='0.0.0.0')

if __name__ == '__main__':
    from scapy.all import get_if_list
    
    interfaces = get_if_list()
    print("Available interfaces:", interfaces)
    
    interface = interfaces[0] if interfaces else 'eth0'
    
    dashboard = NetworkDashboard(interface=interface)
    dashboard.run(debug=True, port=8050)
