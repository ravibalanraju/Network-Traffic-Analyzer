import dash
from dash import dcc, html, Input, Output, State
import plotly.graph_objs as go
import plotly.express as px
import pandas as pd
import threading
import time
from datetime import datetime, timedelta
from packet_capture import PacketCapture
from data_processor import DataProcessor
from anomaly_detector import AnomalyDetector
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
        """Setup dashboard layout"""
        self.app.layout = html.Div([
            html.H1("Network Traffic Analyzer & Anomaly Detector", 
                    style={'textAlign': 'center', 'color': '#2c3e50', 'marginBottom': 30}),
            
            # Control Panel
            html.Div([
                html.Div([
                    html.Label("Network Interface:"),
                    dcc.Input(id='interface-input', type='text', value=self.interface, 
                             style={'marginLeft': 10, 'marginRight': 20}),
                    html.Button('Start Capture', id='start-btn', n_clicks=0, 
                               style={'marginRight': 10, 'backgroundColor': '#27ae60', 'color': 'white'}),
                    html.Button('Stop Capture', id='stop-btn', n_clicks=0,
                               style={'marginRight': 10, 'backgroundColor': '#e74c3c', 'color': 'white'}),
                    html.Button('Train Model', id='train-btn', n_clicks=0,
                               style={'backgroundColor': '#3498db', 'color': 'white'}),
                ], style={'padding': 20, 'backgroundColor': '#ecf0f1', 'borderRadius': 5}),
                
                html.Div(id='status-output', style={'marginTop': 10, 'padding': 10})
            ]),
            
            # Statistics Cards
            html.Div([
                html.Div([
                    html.H3(id='total-packets', children='0', style={'margin': 0}),
                    html.P('Total Packets', style={'margin': 0, 'color': '#7f8c8d'})
                ], className='stat-card', style={'flex': 1, 'padding': 20, 'backgroundColor': '#3498db', 
                                                 'color': 'white', 'borderRadius': 5, 'margin': 10}),
                
                html.Div([
                    html.H3(id='anomaly-count', children='0', style={'margin': 0}),
                    html.P('Anomalies Detected', style={'margin': 0, 'color': '#7f8c8d'})
                ], className='stat-card', style={'flex': 1, 'padding': 20, 'backgroundColor': '#e74c3c', 
                                                 'color': 'white', 'borderRadius': 5, 'margin': 10}),
                
                html.Div([
                    html.H3(id='unique-ips', children='0', style={'margin': 0}),
                    html.P('Unique IPs', style={'margin': 0, 'color': '#7f8c8d'})
                ], className='stat-card', style={'flex': 1, 'padding': 20, 'backgroundColor': '#27ae60', 
                                                 'color': 'white', 'borderRadius': 5, 'margin': 10}),
                
                html.Div([
                    html.H3(id='traffic-rate', children='0 KB/s', style={'margin': 0}),
                    html.P('Traffic Rate', style={'margin': 0, 'color': '#7f8c8d'})
                ], className='stat-card', style={'flex': 1, 'padding': 20, 'backgroundColor': '#f39c12', 
                                                 'color': 'white', 'borderRadius': 5, 'margin': 10}),
            ], style={'display': 'flex', 'flexWrap': 'wrap'}),
            
            # Graphs
            html.Div([
                html.Div([
                    dcc.Graph(id='protocol-pie-chart')
                ], style={'width': '50%', 'display': 'inline-block'}),
                
                html.Div([
                    dcc.Graph(id='traffic-timeline')
                ], style={'width': '50%', 'display': 'inline-block'}),
            ]),
            
            html.Div([
                html.Div([
                    dcc.Graph(id='top-talkers')
                ], style={'width': '50%', 'display': 'inline-block'}),
                
                html.Div([
                    dcc.Graph(id='anomaly-scatter')
                ], style={'width': '50%', 'display': 'inline-block'}),
            ]),
            
            # Anomaly Table
            html.Div([
                html.H3("Recent Anomalies", style={'color': '#2c3e50'}),
                html.Div(id='anomaly-table', style={'overflowX': 'auto'})
            ], style={'marginTop': 30, 'padding': 20, 'backgroundColor': '#ecf0f1', 'borderRadius': 5}),
            
            # Auto-refresh interval
            dcc.Interval(
                id='interval-component',
                interval=2*1000,  # Update every 2 seconds
                n_intervals=0
            ),
            
            # Store data
            dcc.Store(id='packet-data-store', data=[])
        ])
    
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
                return "Ready", []
            
            button_id = ctx.triggered[0]['prop_id'].split('.')[0]
            
            if button_id == 'start-btn':
                if not self.is_capturing:
                    self.interface = interface
                    self.start_capture_thread()
                    return html.Div("✓ Capture started", style={'color': '#27ae60', 'fontWeight': 'bold'}), []
                return html.Div("⚠ Already capturing", style={'color': '#f39c12'}), []
            
            elif button_id == 'stop-btn':
                if self.is_capturing:
                    self.stop_capture_thread()
                    return html.Div("✓ Capture stopped", style={'color': '#e74c3c', 'fontWeight': 'bold'}), []
                return html.Div("⚠ Not capturing", style={'color': '#f39c12'}), []
            
            elif button_id == 'train-btn':
                if len(self.packet_buffer) > 100:
                    self.train_model()
                    return html.Div("✓ Model trained successfully", style={'color': '#3498db', 'fontWeight': 'bold'}), []
                return html.Div("⚠ Need at least 100 packets to train", style={'color': '#f39c12'}), []
            
            return "Ready", []
        
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
                empty_fig.update_layout(title="No data yet")
                return '0', '0', '0', '0 KB/s', empty_fig, empty_fig, empty_fig, empty_fig, "No anomalies detected"
            
            df = pd.DataFrame(self.packet_buffer)
            
            # Process data
            processor = DataProcessor(df)
            df_processed = processor.extract_features()
            
            # Detect anomalies if model is trained
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
            
            # Calculate statistics
            total_packets = len(df_processed)
            unique_ips = df_processed['src_ip'].nunique() + df_processed['dst_ip'].nunique()
            
            # Calculate traffic rate
            if 'timestamp' in df_processed.columns and len(df_processed) > 1:
                df_processed['timestamp'] = pd.to_datetime(df_processed['timestamp'])
                time_span = (df_processed['timestamp'].max() - df_processed['timestamp'].min()).total_seconds()
                if time_span > 0:
                    bytes_per_sec = df_processed['length'].sum() / time_span
                    traffic_rate = f"{bytes_per_sec / 1024:.2f} KB/s"
                else:
                    traffic_rate = "0 KB/s"
            else:
                traffic_rate = "0 KB/s"
            
            # Protocol Distribution Pie Chart
            protocol_counts = df_processed['protocol_name'].value_counts()
            pie_fig = px.pie(
                values=protocol_counts.values,
                names=protocol_counts.index,
                title='Protocol Distribution',
                color_discrete_sequence=px.colors.qualitative.Set3
            )
            
            # Traffic Timeline
            if 'timestamp' in df_processed.columns:
                df_timeline = df_processed.groupby(pd.Grouper(key='timestamp', freq='10S')).size().reset_index(name='count')
                timeline_fig = px.line(
                    df_timeline,
                    x='timestamp',
                    y='count',
                    title='Traffic Over Time (packets per 10s)',
                    labels={'count': 'Packet Count', 'timestamp': 'Time'}
                )
                timeline_fig.update_traces(line_color='#3498db')
            else:
                timeline_fig = go.Figure()
                timeline_fig.update_layout(title="Traffic Over Time")
            
            # Top Talkers
            top_src = df_processed['src_ip'].value_counts().head(10)
            talkers_fig = px.bar(
                x=top_src.values,
                y=top_src.index,
                orientation='h',
                title='Top 10 Source IPs',
                labels={'x': 'Packet Count', 'y': 'IP Address'},
                color=top_src.values,
                color_continuous_scale='Blues'
            )
            
            # Anomaly Scatter Plot
            if 'is_anomaly' in df_processed.columns and 'anomaly_score' in df_processed.columns:
                scatter_df = df_processed.copy()
                scatter_df['status'] = scatter_df['is_anomaly'].map({1: 'Normal', -1: 'Anomaly'})
                scatter_fig = px.scatter(
                    scatter_df,
                    x='length',
                    y='anomaly_score',
                    color='status',
                    title='Anomaly Detection Scatter Plot',
                    labels={'length': 'Packet Size', 'anomaly_score': 'Anomaly Score'},
                    color_discrete_map={'Normal': '#27ae60', 'Anomaly': '#e74c3c'}
                )
            else:
                scatter_fig = go.Figure()
                scatter_fig.update_layout(title="Anomaly Detection (Model not trained)")
            
            # Anomaly Table
            if 'is_anomaly' in df_processed.columns:
                anomalies = df_processed[df_processed['is_anomaly'] == -1].nsmallest(10, 'anomaly_score')
                if len(anomalies) > 0:
                    table = html.Table([
                        html.Thead(html.Tr([
                            html.Th('Timestamp'),
                            html.Th('Source IP'),
                            html.Th('Dest IP'),
                            html.Th('Protocol'),
                            html.Th('Size'),
                            html.Th('Anomaly Score')
                        ])),
                        html.Tbody([
                            html.Tr([
                                html.Td(str(row['timestamp'])[:19] if 'timestamp' in row else 'N/A'),
                                html.Td(row['src_ip']),
                                html.Td(row['dst_ip']),
                                html.Td(row['protocol_name']),
                                html.Td(f"{row['length']} bytes"),
                                html.Td(f"{row['anomaly_score']:.4f}")
                            ]) for idx, row in anomalies.iterrows()
                        ])
                    ], style={'width': '100%', 'borderCollapse': 'collapse', 'border': '1px solid #ddd'})
                else:
                    table = "No anomalies detected"
            else:
                table = "Model not trained yet"
            
            return (
                str(total_packets),
                str(anomaly_count),
                str(unique_ips),
                traffic_rate,
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
                
                # Keep only last 10000 packets to prevent memory issues
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
        self.app.run_server(debug=debug, port=port, host='0.0.0.0')

# Run the dashboard
if __name__ == '__main__':
    from scapy.all import get_if_list
    
    interfaces = get_if_list()
    print("Available interfaces:", interfaces)
    
    # Use first available interface or specify one
    interface = interfaces[0] if interfaces else 'eth0'
    
    dashboard = NetworkDashboard(interface=interface)
    dashboard.run(debug=True, port=8050)
