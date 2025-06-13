package com.example.courseworkLuchnetskyi.controller;

import com.example.courseworkLuchnetskyi.dto.request.PlayerRequestDto;
import com.example.courseworkLuchnetskyi.dto.response.PlayerResponseDto;
import com.example.courseworkLuchnetskyi.service.PlayerService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import jakarta.validation.Valid;
import java.util.List;

import com.example.courseworkLuchnetskyi.dto.PlayerStatisticsDto;
import com.example.courseworkLuchnetskyi.dto.TeamAverageAgeDto;

@RestController
@RequestMapping("/api/players")
@RequiredArgsConstructor
public class PlayerController {

    private final PlayerService playerService;

    @PostMapping
    public ResponseEntity<PlayerResponseDto> createPlayer(@RequestBody @Valid PlayerRequestDto dto) {
        return ResponseEntity.status(HttpStatus.CREATED).body(playerService.createPlayer(dto));
    }

    @GetMapping("/team/{teamId}")
    public ResponseEntity<List<PlayerResponseDto>> getPlayersByTeam(@PathVariable Long teamId) {
        return ResponseEntity.ok(playerService.getPlayersByTeam(teamId));
    }

    @GetMapping("/average-age/{teamId}")
    public ResponseEntity<TeamAverageAgeDto> getAverageAgeForTeam(@PathVariable Long teamId) {
        TeamAverageAgeDto averageAgeDto = playerService.getAverageAgeForTeam(teamId);
        return ResponseEntity.ok(averageAgeDto);
    }

    @PutMapping("/{id}")
    public ResponseEntity<PlayerResponseDto> updatePlayer(@PathVariable Long id,
                                                          @RequestBody @Valid PlayerRequestDto dto) {
        return ResponseEntity.ok(playerService.updatePlayer(id, dto));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deletePlayer(@PathVariable Long id) {
        playerService.deletePlayer(id);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/statistics/{teamId}")
    public ResponseEntity<List<PlayerStatisticsDto>> getPlayerStatistics(@PathVariable Long teamId) {
        List<PlayerStatisticsDto> statistics = playerService.getPlayerStatisticsByTeam(teamId);
        return ResponseEntity.ok(statistics);
    }

}
