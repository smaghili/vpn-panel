import time
import psutil
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from collections import defaultdict, deque

@dataclass
class PerformanceMetrics:
    timestamp: datetime
    cpu_percent: float
    memory_percent: float
    disk_usage_percent: float
    network_bytes_sent: int
    network_bytes_recv: int
    active_connections: int
    response_time_avg: float
    requests_per_second: float
    error_rate: float

class PerformanceMonitor:
    def __init__(self, history_size: int = 1000):
        self.history_size = history_size
        self.metrics_history = deque(maxlen=history_size)
        self.request_times = deque(maxlen=1000)
        self.error_count = 0
        self.total_requests = 0
        self.start_time = datetime.now()
        self.lock = threading.Lock()
        
        # Network stats
        self.last_network_stats = psutil.net_io_counters()
        self.last_network_time = time.time()
        
        # Start monitoring thread
        self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitoring_thread.start()
    
    def _monitoring_loop(self):
        """Background monitoring loop"""
        while True:
            try:
                self._collect_metrics()
                time.sleep(60)  # Collect metrics every minute
            except Exception as e:
                print(f"Error in monitoring loop: {e}")
                time.sleep(60)
    
    def _collect_metrics(self):
        """Collect system performance metrics"""
        try:
            # CPU and Memory
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            
            # Disk usage
            disk = psutil.disk_usage('/')
            disk_usage_percent = (disk.used / disk.total) * 100
            
            # Network stats
            current_network_stats = psutil.net_io_counters()
            current_time = time.time()
            
            network_bytes_sent = current_network_stats.bytes_sent - self.last_network_stats.bytes_sent
            network_bytes_recv = current_network_stats.bytes_recv - self.last_network_stats.bytes_recv
            
            self.last_network_stats = current_network_stats
            self.last_network_time = current_time
            
            # Connection stats
            active_connections = len(psutil.net_connections())
            
            # Application stats
            with self.lock:
                response_time_avg = self._calculate_avg_response_time()
                requests_per_second = self._calculate_requests_per_second()
                error_rate = self._calculate_error_rate()
            
            metrics = PerformanceMetrics(
                timestamp=datetime.now(),
                cpu_percent=cpu_percent,
                memory_percent=memory_percent,
                disk_usage_percent=disk_usage_percent,
                network_bytes_sent=network_bytes_sent,
                network_bytes_recv=network_bytes_recv,
                active_connections=active_connections,
                response_time_avg=response_time_avg,
                requests_per_second=requests_per_second,
                error_rate=error_rate
            )
            
            self.metrics_history.append(metrics)
            
        except Exception as e:
            print(f"Error collecting metrics: {e}")
    
    def record_request(self, response_time: float, is_error: bool = False):
        """Record a request for performance tracking"""
        with self.lock:
            self.request_times.append(response_time)
            self.total_requests += 1
            if is_error:
                self.error_count += 1
    
    def _calculate_avg_response_time(self) -> float:
        """Calculate average response time"""
        if not self.request_times:
            return 0.0
        return sum(self.request_times) / len(self.request_times)
    
    def _calculate_requests_per_second(self) -> float:
        """Calculate requests per second"""
        if not self.request_times:
            return 0.0
        
        # Calculate RPS based on last 60 seconds
        cutoff_time = time.time() - 60
        recent_requests = [rt for rt in self.request_times if rt > cutoff_time]
        return len(recent_requests) / 60.0
    
    def _calculate_error_rate(self) -> float:
        """Calculate error rate percentage"""
        if self.total_requests == 0:
            return 0.0
        return (self.error_count / self.total_requests) * 100
    
    def get_current_metrics(self) -> Optional[PerformanceMetrics]:
        """Get the most recent performance metrics"""
        if self.metrics_history:
            return self.metrics_history[-1]
        return None
    
    def get_metrics_history(self, hours: int = 24) -> List[PerformanceMetrics]:
        """Get performance metrics history for the specified hours"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        return [m for m in self.metrics_history if m.timestamp >= cutoff_time]
    
    def get_system_health(self) -> Dict[str, Any]:
        """Get overall system health status"""
        current_metrics = self.get_current_metrics()
        if not current_metrics:
            return {"status": "unknown", "message": "No metrics available"}
        
        # Define thresholds
        cpu_threshold = 80.0
        memory_threshold = 85.0
        disk_threshold = 90.0
        error_rate_threshold = 5.0
        
        issues = []
        
        if current_metrics.cpu_percent > cpu_threshold:
            issues.append(f"High CPU usage: {current_metrics.cpu_percent:.1f}%")
        
        if current_metrics.memory_percent > memory_threshold:
            issues.append(f"High memory usage: {current_metrics.memory_percent:.1f}%")
        
        if current_metrics.disk_usage_percent > disk_threshold:
            issues.append(f"High disk usage: {current_metrics.disk_usage_percent:.1f}%")
        
        if current_metrics.error_rate > error_rate_threshold:
            issues.append(f"High error rate: {current_metrics.error_rate:.1f}%")
        
        if issues:
            return {
                "status": "warning",
                "message": "System performance issues detected",
                "issues": issues,
                "metrics": current_metrics
            }
        else:
            return {
                "status": "healthy",
                "message": "System is performing well",
                "metrics": current_metrics
            }
performance_monitor = PerformanceMonitor() 